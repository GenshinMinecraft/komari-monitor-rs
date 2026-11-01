#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::too_many_lines
)]

use crate::callbacks::handle_callbacks;
use crate::command_parser::Args;
use crate::data_struct::{BasicInfo, RealTimeInfo};
use crate::dry_run::dry_run;
use crate::get_info::network::network_saver::network_saver;
use crate::utils::{build_urls, connect_ws, init_logger};
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use log::{debug, error, info};
use miniserde::json;
use std::process::exit;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::{CpuRefreshKind, DiskRefreshKind, Disks, MemoryRefreshKind, Networks, RefreshKind};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, watch};
use tokio::time::{Instant, MissedTickBehavior, interval, interval_at, sleep, timeout};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

mod callbacks;
mod command_parser;
mod data_struct;
mod dry_run;
mod get_info;
mod rustls_config;
mod utils;

type LockedWriter = Arc<
    Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>,
>;

const WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const WS_PING_PERIOD: Duration = Duration::from_secs(15);
const WS_PONG_WAIT: Duration = Duration::from_secs(30);
const WS_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const MIN_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
const STABLE_CONNECTION_DURATION: Duration = Duration::from_secs(60);

async fn send_ws_message(writer: &LockedWriter, message: Message) -> Result<(), String> {
    timeout(WS_SEND_TIMEOUT, async {
        let mut writer = writer.lock().await;
        writer.send(message).await
    })
    .await
    .map_err(|_| format!("WebSocket send timed out after {WS_SEND_TIMEOUT:?}"))?
    .map_err(|e| format!("WebSocket send failed: {e}"))
}

fn reconnect_wait(delay: Duration) -> Duration {
    if delay.is_zero() {
        return delay;
    }

    // 在 [delay / 2, delay] 内加入抖动，避免大量客户端同时重连。
    // 此处不需要密码学随机性，以当前时间作为轻量抖动源即可。
    let half = delay / 2;
    let range_nanos = delay.saturating_sub(half).as_nanos();
    let time_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let jitter_nanos = if range_nanos == 0 {
        0
    } else {
        time_nanos % (range_nanos + 1)
    };
    let jitter = Duration::from_nanos(u64::try_from(jitter_nanos).unwrap_or(u64::MAX));
    half.saturating_add(jitter)
}

#[tokio::main]
async fn main() {
    let args = Args::par();

    init_logger(&args.log_level);

    dry_run().await;

    if args.dry_run {
        exit(0);
    }

    let network_config = args.network_config();

    let (http_server, token) = match (args.http_server.clone(), args.token.clone()) {
        (Some(http_server), Some(token)) => (http_server, token),
        (_, _) => {
            error!("The `--http-server` and `--token` parameters must be specified.");
            exit(1);
        }
    };

    for line in args.to_string().lines() {
        debug!("{line}");
    }

    let connection_urls = build_urls(
        http_server.as_ref(),
        args.ws_server.as_ref(),
        token.as_ref(),
    )
    .unwrap_or_else(|e| {
        error!("Failed to parse server address: {e}");
        exit(1);
    });

    for line in connection_urls.to_string().lines() {
        debug!("{line}");
    }

    #[cfg(target_os = "windows")]
    {
        if !args.disable_toast_notify {
            use win_toast_notify::{Action, ActivationType, WinToastNotify};
            WinToastNotify::new()
                .set_title("Komari-monitor-rs Is Running!")
                .set_messages(vec![
                    "Komari-monitor-rs is an application used to monitor your system, granting it near-complete access to your computer. If you did not actively install this program, please check your system immediately. If you have intentionally used this software on your system, please ignore this message or add `--disable-toast-notify` to your startup parameters."
                ])
                .set_actions(vec![
                    Action {
                        activation_type: ActivationType::Protocol,
                        action_content: "komari-monitor".to_string(),
                        arguments: "https://github.com/komari-monitor".to_string(),
                        image_url: None
                    },
                    Action {
                        activation_type: ActivationType::Protocol,
                        action_content: "komari-monitor-rs".to_string(),
                        arguments: "https://github.com/GenshinMinecraft/komari-monitor-rs".to_string(),
                        image_url: None
                    },
                ])
                .show()
                .expect("Failed to show toast notification");
        }
    }

    if !network_config.disable_network_statistics {
        let _listener = tokio::spawn(async move {
            network_saver(&network_config).await;
        });
    } else {
        info!(
            "Network statistics feature disabled. This will fallback to statistics only showing network interface traffic since the current startup"
        );
    }

    let mut reconnect_delay = MIN_RECONNECT_DELAY;

    loop {
        info!("Connecting to real-time WebSocket server...");
        let ws_stream = match connect_ws(
            &connection_urls.ws_real_time,
            args.tls,
            args.ignore_unsafe_cert,
        )
        .await
        {
            Ok(ws_stream) => ws_stream,
            Err(e) => {
                error!("Failed to connect to WebSocket server: {e}");
                let wait = reconnect_wait(reconnect_delay);
                info!("Retrying real-time WebSocket connection in {wait:?}");
                sleep(wait).await;
                reconnect_delay = reconnect_delay
                    .saturating_mul(2)
                    .min(MAX_RECONNECT_DELAY);
                continue;
            }
        };

        let connected_at = Instant::now();
        let (write, mut read) = ws_stream.split();
        let locked_write: LockedWriter = Arc::new(Mutex::new(write));
        let (activity_tx, mut activity_rx) = watch::channel(Instant::now());

        // Handle callbacks
        let mut callback_task = {
            let args_cloned = args.clone();
            let connection_urls_cloned = connection_urls.clone();
            let locked_write_cloned = locked_write.clone();
            tokio::spawn(async move {
                handle_callbacks(
                    &args_cloned,
                    &connection_urls_cloned,
                    &mut read,
                    &locked_write_cloned,
                    &activity_tx,
                )
                .await
            })
        };

        let mut sysinfo_sys = sysinfo::System::new();
        let mut networks = Networks::new_with_refreshed_list();
        let mut disks = Disks::new();
        sysinfo_sys.refresh_cpu_list(
            CpuRefreshKind::nothing()
                .without_cpu_usage()
                .without_frequency(),
        );
        sysinfo_sys.refresh_memory_specifics(MemoryRefreshKind::everything());

        let basic_info = BasicInfo::build(&sysinfo_sys, args.fake, &args.ip_provider).await;

        basic_info.push(connection_urls.basic_info.clone(), args.ignore_unsafe_cert);

        let report_period = Duration::from_millis(args.realtime_info_interval.max(1));
        let mut report_interval = interval(report_period);
        report_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut ping_interval = interval_at(Instant::now() + WS_PING_PERIOD, WS_PING_PERIOD);
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        info!("Real-time WebSocket connected");
        let mut callback_task_completed = false;
        let connection_result: Result<(), String> = loop {
            tokio::select! {
                callback_result = &mut callback_task => {
                    callback_task_completed = true;
                    break match callback_result {
                        Ok(result) => result,
                        Err(e) => Err(format!("WebSocket callback task failed: {e}")),
                    };
                }
                _ = ping_interval.tick() => {
                    let last_activity = *activity_rx.borrow_and_update();
                    if last_activity.elapsed() >= WS_PONG_WAIT {
                        break Err(format!(
                            "WebSocket heartbeat timed out after {WS_PONG_WAIT:?} without receiving data"
                        ));
                    }

                    if let Err(e) = send_ws_message(
                        &locked_write,
                        Message::Ping(Vec::new().into()),
                    ).await {
                        break Err(e);
                    }
                }
                _ = report_interval.tick() => {
            let start_time = tokio::time::Instant::now();
            sysinfo_sys.refresh_specifics(
                RefreshKind::nothing()
                    .with_cpu(CpuRefreshKind::everything().without_frequency())
                    .with_memory(MemoryRefreshKind::everything()),
            );
            networks.refresh(true);
            disks.refresh_specifics(true, DiskRefreshKind::nothing().with_storage());
            let real_time = RealTimeInfo::build(
                &sysinfo_sys,
                &networks,
                &disks,
                args.fake,
                args.realtime_info_interval,
            );

            let json = json::to_string(&real_time);
                    if let Err(e) = send_ws_message(
                        &locked_write,
                        Message::Text(Utf8Bytes::from(json)),
                    ).await {
                        break Err(e);
                    }

                    debug!("Real-time report completed in {:?}", start_time.elapsed());
                }
            }
        };

        error!("Real-time WebSocket disconnected: {}", connection_result.unwrap_err());

        // 尽力发送关闭帧，但绝不让清理过程拖延重连。
        let _ = timeout(WS_CLOSE_TIMEOUT, async {
            let mut writer = locked_write.lock().await;
            writer.send(Message::Close(None)).await
        })
        .await;
        if !callback_task_completed {
            callback_task.abort();
            let _ = callback_task.await;
        }

        let connected_for = connected_at.elapsed();
        let stable = connected_for >= STABLE_CONNECTION_DURATION;
        if stable {
            reconnect_delay = MIN_RECONNECT_DELAY;
        }

        let wait = reconnect_wait(reconnect_delay);
        info!("Retrying real-time WebSocket connection in {wait:?}");
        sleep(wait).await;
        if !stable {
            reconnect_delay = reconnect_delay
                .saturating_mul(2)
                .min(MAX_RECONNECT_DELAY);
        }
    }
}
