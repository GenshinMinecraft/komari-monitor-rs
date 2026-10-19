use crate::data_struct::Connections;
use log::trace;
use sysinfo::Networks;

#[cfg(target_os = "linux")]
mod netlink;
pub mod network_saver;

// Use lock-free atomics on platforms that support them for best performance.
#[cfg(target_has_atomic = "64")]
mod imp {
    use super::filter_network;
    use crate::data_struct::Network;
    use log::trace;
    use std::sync::atomic::{AtomicI64, Ordering};
    use sysinfo::Networks;

    static TRAFFIC_OFFSET_TX: AtomicI64 = AtomicI64::new(0);
    static TRAFFIC_OFFSET_RX: AtomicI64 = AtomicI64::new(0);

    pub fn update_traffic_offset(offset_tx: i64, offset_rx: i64) {
        TRAFFIC_OFFSET_TX.store(offset_tx, Ordering::Relaxed);
        TRAFFIC_OFFSET_RX.store(offset_rx, Ordering::Relaxed);
        trace!("Traffic offset updated to: tx={}, rx={}", offset_tx, offset_rx);
    }

    pub fn realtime_network(network: &Networks, interval: std::time::Duration) -> Network {
        let (up, down, total_up, total_down) = filter_network(network);

        let offset_tx = TRAFFIC_OFFSET_TX.load(Ordering::Relaxed);
        let offset_rx = TRAFFIC_OFFSET_RX.load(Ordering::Relaxed);

        let cycle_total_up = (total_up as i64 + offset_tx).max(0) as u64;
        let cycle_total_down = (total_down as i64 + offset_rx).max(0) as u64;

        let interval_s = interval.as_secs_f64();
        Network {
            up: if interval_s > 0.0 { (up as f64 / interval_s) as u64 } else { 0 },
            down: if interval_s > 0.0 { (down as f64 / interval_s) as u64 } else { 0 },
            total_up: cycle_total_up,
            total_down: cycle_total_down,
        }
    }
}

// Use a RwLock as a fallback for older 32-bit platforms without 64-bit atomic support.
#[cfg(not(target_has_atomic = "64"))]
mod imp {
    use super::filter_network;
    use crate::data_struct::Network;
    use log::{trace, warn};
    use std::sync::RwLock;
    use sysinfo::Networks;

    static TRAFFIC_OFFSET: RwLock<(i64, i64)> = RwLock::new((0, 0));

    pub fn update_traffic_offset(offset_tx: i64, offset_rx: i64) {
        if let Ok(mut offset) = TRAFFIC_OFFSET.write() {
            *offset = (offset_tx, offset_rx);
            trace!("Traffic offset updated to: tx={}, rx={}", offset_tx, offset_rx);
        } else {
            warn!("Failed to acquire write lock on traffic offset, it may be poisoned.");
        }
    }

    pub fn realtime_network(network: &Networks, interval: std::time::Duration) -> Network {
        let (up, down, total_up, total_down) = filter_network(network);

        let (offset_tx, offset_rx) = if let Ok(offset) = TRAFFIC_OFFSET.read() {
            *offset
        } else {
            warn!("Failed to acquire read lock on traffic offset, it may be poisoned. Using (0,0).");
            (0, 0)
        };

        let cycle_total_up = (total_up as i64 + offset_tx).max(0) as u64;
        let cycle_total_down = (total_down as i64 + offset_rx).max(0) as u64;

        let interval_s = interval.as_secs_f64();
        Network {
            up: if interval_s > 0.0 { (up as f64 / interval_s) as u64 } else { 0 },
            down: if interval_s > 0.0 { (down as f64 / interval_s) as u64 } else { 0 },
            total_up: cycle_total_up,
            total_down: cycle_total_down,
        }
    }
}

pub use imp::{realtime_network, update_traffic_offset};

#[cfg(target_os = "linux")]
pub fn realtime_connections() -> Connections {
    use netlink::connections_count_with_protocol;
    let tcp4 =
        connections_count_with_protocol(libc::AF_INET as u8, libc::IPPROTO_TCP as u8).unwrap_or(0);
    let tcp6 =
        connections_count_with_protocol(libc::AF_INET6 as u8, libc::IPPROTO_TCP as u8).unwrap_or(0);
    let udp4 =
        connections_count_with_protocol(libc::AF_INET as u8, libc::IPPROTO_UDP as u8).unwrap_or(0);
    let udp6 =
        connections_count_with_protocol(libc::AF_INET6 as u8, libc::IPPROTO_UDP as u8).unwrap_or(0);
    let connections = Connections {
        tcp: tcp4 + tcp6,
        udp: udp4 + udp6,
    };
    trace!(
        "REALTIME CONNECTIONS successfully retrieved: {:?}",
        connections
    );
    connections
}

#[cfg(target_os = "windows")]
pub fn realtime_connections() -> Connections {
    use netstat2::{ProtocolFlags, ProtocolSocketInfo, iterate_sockets_info_without_pids};
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let Ok(sockets_iterator) = iterate_sockets_info_without_pids(proto_flags) else {
        let connections = Connections { tcp: 0, udp: 0 };
        trace!("REALTIME CONNECTIONS successfully retrieved: {connections:?}");
        return connections;
    };

    let (mut tcp_count, mut udp_count) = (0, 0);

    for info_result in sockets_iterator.flatten() {
        match info_result.protocol_socket_info {
            ProtocolSocketInfo::Tcp(_) => tcp_count += 1,
            ProtocolSocketInfo::Udp(_) => udp_count += 1,
        }
    }

    let connections = Connections {
        tcp: tcp_count,
        udp: udp_count,
    };
    trace!("REALTIME CONNECTIONS successfully retrieved: {connections:?}");
    connections
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn realtime_connections() -> Connections {
    let connections = Connections { tcp: 0, udp: 0 };
    trace!(
        "REALTIME CONNECTIONS successfully retrieved: {:?}",
        connections
    );
    connections
}

pub fn filter_network(network: &Networks) -> (u64, u64, u64, u64) {
    let mut total_up = 0;
    let mut total_down = 0;
    let mut up = 0;
    let mut down = 0;

    static FILTER_KEYWORDS: &[&str] = &[
        "br", "cni", "docker", "podman", "flannel", "lo", "veth", "virbr", "vmbr", "tap", "tun",
        "fwln", "fwpr",
    ];

    for (name, data) in network {
        let should_filter = FILTER_KEYWORDS
            .iter()
            .any(|&keyword| name.contains(keyword));

        if should_filter || data.mac_address().0 == [0, 0, 0, 0, 0, 0] {
            continue;
        }

        total_up += data.total_transmitted();
        total_down += data.total_received();
        up += data.transmitted();
        down += data.received();
    }

    (up, down, total_up, total_down)
}
