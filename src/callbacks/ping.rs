use icmp_socket::packet::WithEchoRequest;
use icmp_socket::{
    IcmpSocket, IcmpSocket4, IcmpSocket6, Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet,
};
use log::{debug, warn};
use miniserde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::AtomicU16;
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::net::TcpStream;
use tokio::net::lookup_host;
use tokio::time::Instant;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PingEvent {
    message: String,
    ping_task_id: u64,
    ping_type: String,
    ping_target: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PingEventCallback {
    #[serde(rename = "type")]
    pub type_str: String,
    pub task_id: u64,
    pub ping_type: String,
    pub value: Option<i64>,
    pub finished_at: String,
}

fn split_address(addr: &str) -> (String, u16) {
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return (ip.to_string(), 80);
    }

    if let Some(pos) = addr.rfind(':') {
        let (host_part, port_part) = addr.split_at(pos);
        let port_part = &port_part[1..]; // Remove colon

        let host = host_part.trim_start_matches('[').trim_end_matches(']');

        if port_part.is_empty() {
            return (host.to_string(), 80);
        }

        if let Ok(port) = port_part.parse::<u16>() {
            return (host.to_string(), port);
        }

        return (host.to_string(), 80);
    }

    (addr.to_string(), 80)
}

pub async fn ping_target(utf8_str: &str) -> Result<PingEventCallback, String> {
    let ping_event: PingEvent =
        miniserde::json::from_str(utf8_str).map_err(|_| "Failed to parse PingEvent".to_string())?;

    match ping_event.ping_type.as_str() {
        "icmp" => {
            #[cfg(not(target_os = "windows"))]
            if std::env::var("USER").unwrap_or_default() != "root" {
                return Err(String::from(
                    "Cannot create Raw socket in non-privileged environment",
                ));
            }

            match get_ip_from_string(&ping_event.ping_target).await {
                Ok(ip) => {
                    debug!("DNS resolution: {}: {}", ping_event.ping_target, ip);
                    match ip {
                        IpAddr::V4(ip) => icmp_ipv4(ip, ping_event.ping_task_id),
                        IpAddr::V6(ip) => icmp_ipv6(ip, ping_event.ping_task_id),
                    }
                }
                Err(e) => {
                    warn!("DNS resolution failed: {}: {}", ping_event.ping_target, e);
                    Err(String::from("Failed to resolve IP address"))
                }
            }
        }
        "tcp" => {
            let start_time = Instant::now();

            let (ip, port) = split_address(&ping_event.ping_target);

            let ping = match tokio::time::timeout(
                Duration::from_secs(10),
                TcpStream::connect(format!("{ip}:{port}")),
            )
            .await
            {
                Err(_) => Err("Tcping timeout".to_string()),
                Ok(Ok(_)) => Ok(()),
                Ok(Err(_)) => Err("Failed to connect".to_string()),
            };

            let rtt = start_time.elapsed();

            let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
            let finished_at = now.format(&Rfc3339).unwrap_or_default();

            if let Ok(()) = ping {
                Ok(PingEventCallback {
                    type_str: String::from("ping_result"),
                    task_id: ping_event.ping_task_id,
                    ping_type: String::from("tcp"),
                    value: i64::try_from(rtt.as_millis()).ok(),
                    finished_at,
                })
            } else {
                Ok(PingEventCallback {
                    type_str: String::from("ping_result"),
                    task_id: ping_event.ping_task_id,
                    ping_type: String::from("tcp"),
                    value: Some(-1),
                    finished_at,
                })
            }
        }
        "http" => {
            let start_time = Instant::now();

            #[cfg(feature = "ureq-support")]
            let result = ureq::get(&ping_event.ping_target) // Avoid cloning
                .header("User-Agent", "curl/11.45.14")
                .call()
                .is_ok();

            #[cfg(feature = "nyquest-support")]
            let result = {
                use nyquest::Request;
                let client = crate::utils::create_nyquest_client(false);
                let request = Request::get(ping_event.ping_target);
                client.request(request).is_ok()
            };

            let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
            let finished_at = now.format(&Rfc3339).unwrap_or_default();

            if result {
                Ok(PingEventCallback {
                    type_str: String::from("ping_result"),
                    task_id: ping_event.ping_task_id,
                    ping_type: String::from("http"),
                    value: i64::try_from(start_time.elapsed().as_millis()).ok(),
                    finished_at,
                })
            } else {
                Ok(PingEventCallback {
                    type_str: String::from("ping_result"),
                    task_id: ping_event.ping_task_id,
                    ping_type: String::from("http"),
                    value: Some(-1),
                    finished_at,
                })
            }
        }
        _ => Err(format!("Ping Error: Not Support: {}", ping_event.ping_type)),
    }
}

pub async fn get_ip_from_string(host_or_ip: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = IpAddr::from_str(host_or_ip) {
        return Ok(ip);
    }

    let host_with_port = format!("{host_or_ip}:80");
    match lookup_host(&host_with_port).await {
        // Avoid cloning
        Ok(mut ip_addresses) => {
            if let Some(first_socket_addr) = ip_addresses.next() {
                Ok(first_socket_addr.ip())
            } else {
                Err(format!(
                    "No IP addresses found for the domain: {host_or_ip}"
                ))
            }
        }
        Err(e) => Err(format!("Error looking up domain: {e}")),
    }
}

pub fn icmp_ipv4(ip: Ipv4Addr, task_id: u64) -> Result<PingEventCallback, String> {
    let Ok(mut socket4) = IcmpSocket4::new() else {
        return Err(String::from("Failed to create Raw socket"));
    };

    if socket4
        .bind("0.0.0.0".parse::<Ipv4Addr>().unwrap())
        .is_err()
    {
        return Err(String::from("Failed to bind Raw socket"));
    }

    let identifier = get_identifier();
    let packet = Icmpv4Packet::with_echo_request(
        identifier,
        0,
        vec![
            0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20,
            0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73, 0x20, 0x62, 0x75, 0x74,
            0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20, 0x6b, 0x6e,
            0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20,
        ],
    )
    .unwrap();

    let timeout = Duration::from_secs(3);
    let send_time = Instant::now();
    if socket4.send_to(ip, packet).is_err() {
        let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        let finished_at = now.format(&Rfc3339).unwrap_or_default();

        return Ok(PingEventCallback {
            type_str: String::from("ping_result"),
            task_id,
            ping_type: String::from("icmp"),
            value: Some(-1),
            finished_at,
        });
    }

    loop {
        let new_timeout = timeout.checked_sub(send_time.elapsed());
        if new_timeout.is_none() {
            break;
        }
        socket4.set_timeout(new_timeout);

        let Ok((resp, _)) = socket4.rcv_from() else {
            break;
        };

        if let Icmpv4Message::EchoReply {
            identifier: resp_id,
            sequence: _,
            payload: _,
        } = resp.message
            && resp_id == identifier
        {
            let rtt = send_time.elapsed();

            let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
            let finished_at = now.format(&Rfc3339).unwrap_or_default();

            return Ok(PingEventCallback {
                type_str: String::from("ping_result"),
                task_id,
                ping_type: String::from("icmp"),
                value: i64::try_from(rtt.as_millis()).ok(),
                finished_at,
            });
        }
    }

    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    let finished_at = now.format(&Rfc3339).unwrap_or_default();

    Ok(PingEventCallback {
        type_str: String::from("ping_result"),
        task_id,
        ping_type: String::from("icmp"),
        value: Some(-1),
        finished_at,
    })
}

pub fn icmp_ipv6(ip: Ipv6Addr, task_id: u64) -> Result<PingEventCallback, String> {
    let Ok(mut socket6) = IcmpSocket6::new() else {
        return Err(String::from("Failed to create Raw socket"));
    };

    if socket6.bind("::0".parse::<Ipv6Addr>().unwrap()).is_err() {
        return Err(String::from("Failed to bind Raw socket"));
    }

    let identifier = get_identifier();
    let packet = Icmpv6Packet::with_echo_request(
        identifier,
        0,
        vec![
            0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20,
            0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73, 0x20, 0x62, 0x75, 0x74,
            0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20, 0x6b, 0x6e,
            0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20,
        ],
    )
    .unwrap();

    let timeout = Duration::from_secs(3);
    let send_time = Instant::now();
    if socket6.send_to(ip, packet).is_err() {
        let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        let finished_at = now.format(&Rfc3339).unwrap_or_default();

        return Ok(PingEventCallback {
            type_str: String::from("ping_result"),
            task_id,
            ping_type: String::from("icmp"),
            value: Some(-1),
            finished_at,
        });
    }

    while send_time.elapsed() < timeout {
        let new_timeout = timeout.checked_sub(send_time.elapsed());
        if new_timeout.is_none() {
            break;
        }
        socket6.set_timeout(new_timeout);

        let Ok((resp, _)) = socket6.rcv_from() else {
            break;
        };

        if let Icmpv6Message::EchoReply {
            identifier: resp_id,
            sequence: _,
            payload: _,
        } = resp.message
            && resp_id == task_id as u16
        {
            let rtt = send_time.elapsed();

            let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
            let finished_at = now.format(&Rfc3339).unwrap_or_default();

            return Ok(PingEventCallback {
                type_str: String::from("ping_result"),
                task_id,
                ping_type: String::from("icmp"),
                value: i64::try_from(rtt.as_millis()).ok(),
                finished_at,
            });
        }
    }

    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    let finished_at = now.format(&Rfc3339).unwrap_or_default();

    Ok(PingEventCallback {
        type_str: String::from("ping_result"),
        task_id,
        ping_type: String::from("icmp"),
        value: Some(-1),
        finished_at,
    })
}

fn get_identifier() -> u16 {
    static GENERATOR: std::sync::LazyLock<AtomicU16> = std::sync::LazyLock::new(|| {
        AtomicU16::new(std::process::id() as u16 ^ OffsetDateTime::now_utc().millisecond())
    });

    (&*GENERATOR).fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
