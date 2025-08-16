use crate::data_struct::{Connections, Cpu, Disk, Load, Network, Ram, Swap};
use miniserde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
// use netstat2::iterate_sockets_info_without_pids;
use sysinfo::{Disks, Networks, System};
use tokio::task::JoinHandle;

pub fn arch() -> String {
    // 直接返回常量，避免to_string()
    std::env::consts::ARCH.to_string()
}

pub struct CPUInfoWithOutUsage {
    pub name: String,
    pub cores: u16,
}

pub fn cpu_info_without_usage(sysinfo_sys: &System) -> CPUInfoWithOutUsage {
    let cores = u16::try_from(sysinfo_sys.cpus().len()).unwrap_or(0);
    let mut hashset = HashSet::new();
    for cpu in sysinfo_sys.cpus() {
        hashset.insert(cpu.brand().to_string());
    }
    let name = hashset.into_iter().collect::<Vec<String>>().join(", ");

    CPUInfoWithOutUsage { name, cores }
}

#[derive(Debug)]
pub struct MemDiskInfoWithOutUsage {
    pub mem_total: u64,
    pub swap_total: u64,
    pub disk_total: u64,
}

pub fn mem_info_without_usage(sysinfo_sys: &System) -> MemDiskInfoWithOutUsage {
    let mem_total = sysinfo_sys.total_memory();
    let swap_total = sysinfo_sys.total_swap();

    let disk_list = Disks::new_with_refreshed_list();
    let mut all_disk_space: u64 = 0;
    for disk in &disk_list {
        all_disk_space += disk.total_space();
    }

    MemDiskInfoWithOutUsage {
        mem_total,
        swap_total,
        disk_total: all_disk_space,
    }
}

pub struct IPInfo {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

#[derive(Serialize, Deserialize)]
struct IpIo {
    ip: String,
}

pub async fn ip() -> IPInfo {
    let ipv4: JoinHandle<Option<Ipv4Addr>> = tokio::spawn(async move {
        let Ok(mut resp) = ureq::get("https://ipinfo.io/")
            .header("User-Agent", "curl/8.7.1")
            .call()
        else {
            return None;
        };

        let Ok(body) = resp.body_mut().read_to_string() else {
            return None;
        };

        let json: IpIo = if let Ok(json) = miniserde::json::from_str(&body) {
            json
        } else {
            return None;
        };

        Ipv4Addr::from_str(&json.ip).ok()
    });

    let ipv6: JoinHandle<Option<Ipv6Addr>> = tokio::spawn(async move {
        let Ok(mut resp) = ureq::get("https://v6.ipinfo.io/")
            .header("User-Agent", "curl/8.7.1")
            .call()
        else {
            return None;
        };

        let Ok(body) = resp.body_mut().read_to_string() else {
            return None;
        };

        let json: IpIo = if let Ok(json) = miniserde::json::from_str(&body) {
            json
        } else {
            return None;
        };

        Ipv6Addr::from_str(&json.ip).ok()
    });

    IPInfo {
        ipv4: ipv4.await.unwrap(),
        ipv6: ipv6.await.unwrap(),
    }
}

pub struct OsInfo {
    pub os: String,
    pub version: String,
    pub virtualization: String,
}

pub async fn os() -> OsInfo {
    let os = format!(
        "{} {}",
        System::name().unwrap_or_default(),
        System::os_version().unwrap_or_default()
    );
    let kernel_version = System::kernel_version().unwrap_or("Unknown".to_string());

    #[cfg(target_os = "linux")]
    let virt = heim_virt::detect()
        .await
        .unwrap_or(heim_virt::Virtualization::Unknown)
        .as_str()
        .to_string();

    #[cfg(not(target_os = "linux"))]
    let virt = "Unknown".to_string();

    OsInfo {
        os,
        version: kernel_version,
        virtualization: virt,
    }
}

pub fn realtime_cpu(sysinfo_sys: &System) -> Cpu {
    let cpus = sysinfo_sys.cpus();
    let mut avg = 0.0;
    for cpu in cpus {
        avg += cpu.cpu_usage();
    }
    let avg = f64::from(avg) / cpus.len() as f64;

    Cpu { usage: avg }
}

pub fn realtime_mem(sysinfo_sys: &System) -> Ram {
    Ram {
        used: sysinfo_sys.total_memory() - sysinfo_sys.available_memory(),
    }
}

pub fn realtime_swap(sysinfo_sys: &System) -> Swap {
    Swap {
        used: sysinfo_sys.used_swap(),
    }
}

pub fn realtime_disk(disk: &Disks) -> Disk {
    let mut used_disk: u64 = 0;
    for disk in disk {
        used_disk += disk.total_space() - disk.available_space();
    }

    Disk { used: used_disk }
}

#[cfg(not(target_os = "windows"))]
pub fn realtime_load() -> Load {
    let load = System::load_average();
    Load {
        load1: load.one,
        load5: load.five,
        load15: load.fifteen,
    }
}

#[cfg(target_os = "windows")]
pub fn realtime_load() -> Load {
    Load {
        load1: 0.0,
        load5: 0.0,
        load15: 0.0,
    }
}

pub static mut DURATION: f64 = 0.0;

pub fn realtime_network(network: &Networks) -> Network {
    let mut total_up = 0;
    let mut total_down = 0;
    let mut up = 0;
    let mut down = 0;

    for (_, data) in network {
        total_up += data.total_transmitted();
        total_down += data.total_received();
        up += data.transmitted();
        down += data.received();
    }

    unsafe {
        Network {
            up: (up as f64 / DURATION) as u64,
            down: (down as f64 / DURATION) as u64,
            total_up,
            total_down,
        }
    }
}

#[cfg(target_os = "linux")]
pub fn realtime_connections() -> Connections {
    use netstat2::{
        AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, iterate_sockets_info_without_pids,
    };
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let Ok(sockets_iterator) = iterate_sockets_info_without_pids(af_flags, proto_flags) else {
        return Connections { tcp: 0, udp: 0 };
    };

    let (mut tcp_count, mut udp_count) = (0, 0);

    for info_result in sockets_iterator.flatten() {
        match info_result.protocol_socket_info {
            ProtocolSocketInfo::Tcp(_) => tcp_count += 1,
            ProtocolSocketInfo::Udp(_) => udp_count += 1,
        }
    }

    Connections {
        tcp: tcp_count,
        udp: udp_count,
    }
}

#[cfg(target_os = "windows")]
pub fn realtime_connections() -> Connections {
    use netstat2::{ProtocolFlags, ProtocolSocketInfo, iterate_sockets_info_without_pids};
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets_iterator = match iterate_sockets_info_without_pids(proto_flags) {
        Ok(iterator) => iterator,
        Err(_) => return Connections { tcp: 0, udp: 0 },
    };

    let (mut tcp_count, mut udp_count) = (0, 0);

    for info_result in sockets_iterator {
        if let Ok(info) = info_result {
            match info.protocol_socket_info {
                ProtocolSocketInfo::Tcp(_) => tcp_count += 1,
                ProtocolSocketInfo::Udp(_) => udp_count += 1,
            }
        }
    }

    Connections {
        tcp: tcp_count,
        udp: udp_count,
    }
}

#[cfg(target_os = "macos")]
pub fn realtime_connections() -> Connections {
    Connections { tcp: 0, udp: 0 }
}

pub fn realtime_uptime() -> u64 {
    System::uptime()
}

pub fn realtime_process() -> u64 {
    let mut process_count = 0;

    let Ok(entries) = fs::read_dir("/proc") else {
        return 0;
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        if let Some(name_str) = file_name.to_str() {
            if name_str.parse::<u32>().is_ok() {
                process_count += 1;
            }
        }
    }

    process_count as u64
}
