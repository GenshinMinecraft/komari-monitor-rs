use crate::command_parser::IpProvider;

use crate::get_info::cpu::{arch, cpu_info_without_usage, realtime_cpu};
use crate::get_info::ip::ip;
use crate::get_info::load::realtime_load;
use crate::get_info::mem::{mem_info_without_usage, realtime_disk, realtime_mem, realtime_swap};
use crate::get_info::network::{realtime_connections, realtime_network};
use crate::get_info::os::os;
use crate::get_info::{realtime_process, realtime_uptime};
use log::{debug, error, info};
use miniserde::{Deserialize, Serialize};
use std::time::Duration;
use sysinfo::{Disks, Networks};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BasicInfo {
    pub arch: String,
    pub cpu_cores: u64,
    pub cpu_name: String,
    pub gpu_name: String, // Not supported yet

    pub disk_total: u64,
    pub swap_total: u64,
    pub mem_total: u64,

    pub ipv4: Option<String>,
    pub ipv6: Option<String>,

    pub os: String,
    pub version: String,
    pub kernel_version: String,
    pub virtualization: String,
}

impl BasicInfo {
    pub async fn build(sysinfo_sys: &sysinfo::System, fake: f64, ip_provider: &IpProvider) -> Self {
        let cpu = cpu_info_without_usage(sysinfo_sys);
        let mem_disk = mem_info_without_usage(sysinfo_sys);
        let (ip, os) = tokio::join!(ip(ip_provider), os());

        let fake_cpu_cores = (f64::from(cpu.cores) * fake) as u64;
        let fake_disk_total = (mem_disk.disk as f64 * fake) as u64;
        let fake_swap_total = (mem_disk.swap as f64 * fake) as u64;
        let fake_mem_total = (mem_disk.mem as f64 * fake) as u64;

        let basic_info = Self {
            arch: arch(),
            cpu_cores: fake_cpu_cores,
            cpu_name: cpu.name,
            gpu_name: String::new(),
            disk_total: fake_disk_total,
            swap_total: fake_swap_total,
            mem_total: fake_mem_total,
            ipv4: ip.ipv4.map(|ip| ip.to_string()),
            ipv6: ip.ipv6.map(|ip| ip.to_string()),
            os: os.os,
            version: format!("komari-monitor-rs {}", env!("CARGO_PKG_VERSION")),
            kernel_version: os.version,
            virtualization: os.virtualization,
        };

        debug!("Basic Info successfully retrieved: {basic_info:?}");

        basic_info
    }

    pub fn push(&self, basic_info_url: String, ignore_unsafe_cert: bool) {
        let json_string = miniserde::json::to_string(self);
        #[cfg(feature = "ureq-support")]
        {
            use crate::utils::create_ureq_agent;
            let agent = create_ureq_agent(ignore_unsafe_cert);
            let resp = agent
                .post(basic_info_url)
                .header("User-Agent", "curl/11.45.14-rs")
                .send(&json_string);

            let resp = match resp {
                Ok(resp) => resp,
                Err(e) => {
                    error!("Failed to push Basic Info: {e}");
                    return;
                }
            };

            if resp.status().is_success() {
                info!("Successfully pushed Basic Info");
            } else {
                error!(
                    "Failed to push Basic Info, HTTP status code: {}",
                    resp.status()
                );
            }
        }
        #[cfg(feature = "nyquest-support")]
        {
            use nyquest::Body;
            use nyquest::Request;
            let client = crate::utils::create_nyquest_client(ignore_unsafe_cert);
            let body = Body::text(json_string, "application/json");
            let resp = client.request(Request::post(basic_info_url).with_body(body));

            let resp = match resp {
                Ok(resp) => resp,
                Err(e) => {
                    error!("Failed to push Basic Info: {e}");
                    return;
                }
            };

            if resp.status().is_successful() {
                info!("Successfully pushed Basic Info");
            } else {
                error!(
                    "Failed to push Basic Info, HTTP status code: {}",
                    resp.status()
                );
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cpu {
    pub usage: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Ram {
    pub used: u64,
    pub total: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Swap {
    pub used: u64,
    pub total: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Disk {
    pub used: u64,
    pub total: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Load {
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Network {
    pub up: u64,
    pub down: u64,
    #[serde(rename = "totalUp")]
    pub total_up: u64,

    #[serde(rename = "totalDown")]
    pub total_down: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Connections {
    pub tcp: u64,
    pub udp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RealTimeInfo {
    pub cpu: Cpu,
    pub ram: Ram,
    pub swap: Swap,
    pub disk: Disk,
    pub load: Load,
    pub network: Network,
    pub connections: Connections,
    pub uptime: u64,
    pub process: u64,
    pub message: String,
}

impl RealTimeInfo {
    pub fn build(
        sysinfo_sys: &sysinfo::System,
        network: &Networks,
        disk: &Disks,
        fake: f64,
        interval: Duration,
    ) -> Self {
        let cpu = realtime_cpu(sysinfo_sys);

        let ram = realtime_mem(sysinfo_sys);
        let fake_ram_used = (ram.used as f64 * fake) as u64;
        let fake_ram_total = (ram.total as f64 * fake) as u64;

        let swap = realtime_swap(sysinfo_sys);
        let fake_swap_used = (swap.used as f64 * fake) as u64;
        let fake_swap_total = (swap.total as f64 * fake) as u64;

        let disk_info = realtime_disk(disk);
        let fake_disk_used = (disk_info.used as f64 * fake) as u64;
        let fake_disk_total = (disk_info.total as f64 * fake) as u64;

        let load = realtime_load();
        let fake_load1 = load.load1 * fake;
        let fake_load5 = load.load5 * fake;
        let fake_load15 = load.load15 * fake;

        let network_info = realtime_network(network, interval);
        let fake_network_up = (network_info.up as f64 * fake) as u64;
        let fake_network_down = (network_info.down as f64 * fake) as u64;
        let fake_network_total_up = (network_info.total_up as f64 * fake) as u64;
        let fake_network_total_down = (network_info.total_down as f64 * fake) as u64;

        let connections = realtime_connections();
        let fake_connections_tcp = (connections.tcp as f64 * fake) as u64;
        let fake_connections_udp = (connections.udp as f64 * fake) as u64;

        let process = realtime_process();
        let fake_process = (process as f64 * fake) as u64;

        let realtime_info = Self {
            cpu,
            ram: Ram {
                used: fake_ram_used,
                total: fake_ram_total,
            },
            swap: Swap {
                used: fake_swap_used,
                total: fake_swap_total,
            },
            disk: Disk {
                used: fake_disk_used,
                total: fake_disk_total,
            },
            load: Load {
                load1: fake_load1,
                load5: fake_load5,
                load15: fake_load15,
            },
            network: Network {
                up: fake_network_up,
                down: fake_network_down,
                total_up: fake_network_total_up,
                total_down: fake_network_total_down,
            },
            connections: Connections {
                tcp: fake_connections_tcp,
                udp: fake_connections_udp,
            },
            uptime: realtime_uptime(),
            process: fake_process,
            message: String::new(),
        };

        debug!("Real-Time Info successfully retrieved: {realtime_info:?}");

        realtime_info
    }
}
