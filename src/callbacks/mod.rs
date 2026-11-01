use crate::callbacks::exec::exec_command;
use crate::callbacks::ping::ping_target;
use crate::callbacks::pty::{get_pty_ws_link, handle_pty_session};
use crate::command_parser::Args;
use crate::utils::{ConnectionUrls, connect_ws};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use log::{debug, error, info};
use miniserde::{Deserialize, Serialize, json};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, watch};
use tokio::time::{Duration, Instant, timeout};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub mod exec;
pub mod ping;
pub mod pty;

#[derive(Serialize, Deserialize)]
struct Msg {
    message: String,
}

type Reader = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;
type LockedWriter = Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>;
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn handle_callbacks(
    args: &Args,
    connection_urls: &ConnectionUrls,
    reader: &mut Reader,
    locked_writer: &LockedWriter,
    activity_tx: &watch::Sender<Instant>,
) -> Result<(), String> {
    loop {
        let msg = match reader.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => return Err(format!("WebSocket receive failed: {e}")),
            None => return Err("WebSocket stream ended".to_string()),
        };
        let _ = activity_tx.send(Instant::now());

        let utf8 = match msg {
            Message::Pong(_) => {
                debug!("Received WebSocket pong from main server");
                continue;
            }
            Message::Text(utf8) if utf8.as_str().is_empty() => {
                debug!("Received empty text message from main server");
                continue;
            }
            Message::Text(utf8) => utf8,
            _ => continue,
        };

        info!("Received message from main server: {}", utf8.as_str());

        let json: Msg = if let Ok(value) = json::from_str(utf8.as_str()) {
            value
        } else {
            continue;
        };

        let utf8_cloned = utf8.clone();

        match json.message.as_str() {
            "exec" => {
                if args.terminal {
                    tokio::spawn({
                        let utf8_cloned_for_exec = utf8_cloned.clone();
                        let exec_callback_url = connection_urls.exec_callback.clone();
                        let ignore_unsafe_cert = args.ignore_unsafe_cert;

                        async move {
                            if let Err(e) = exec_command(
                                &utf8_cloned_for_exec,
                                exec_callback_url,
                                &ignore_unsafe_cert,
                            )
                            .await
                            {
                                error!("Exec Error: {e}");
                            }
                        }
                    });
                } else {
                    error!("Terminal feature is disabled");
                }
            }

            "ping" => {
                let locked_write_for_ping = locked_writer.clone();
                tokio::spawn(async move {
                    match ping_target(&utf8_cloned).await {
                        Ok(json_res) => {
                            info!("Ping successful: {}", json::to_string(&json_res));
                            match timeout(WS_SEND_TIMEOUT, async {
                                let mut write = locked_write_for_ping.lock().await;
                                write
                                    .send(Message::Text(Utf8Bytes::from(json::to_string(&json_res))))
                                    .await
                            })
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => error!("Error occurred while pushing ping result: {e}"),
                                Err(_) => error!(
                                    "Timed out after {WS_SEND_TIMEOUT:?} while pushing ping result"
                                ),
                            }
                        }
                        Err(err) => {
                            error!("Ping Error: {err}");
                        }
                    }
                });
            }

            "terminal" => {
                if args.terminal {
                    let ws_terminal_url = connection_urls.clone().ws_terminal.clone();
                    let args = args.clone();
                    let utf8_cloned = utf8_cloned.clone();

                    tokio::spawn(async move {
                        let ws_url = match get_pty_ws_link(&utf8_cloned, &ws_terminal_url) {
                            Ok(ws_url) => ws_url,
                            Err(e) => {
                                error!("Failed to get PTY WebSocket URL: {e}");
                                return;
                            }
                        };

                        let ws_stream =
                            match connect_ws(&ws_url, args.tls, args.ignore_unsafe_cert).await {
                                Ok(ws_stream) => ws_stream,
                                Err(e) => {
                                    error!("Failed to connect to PTY WebSocket: {e}");
                                    return;
                                }
                            };

                        if let Err(e) = handle_pty_session(ws_stream, &args.terminal_entry).await {
                            error!("PTY WebSocket handling error: {e}");
                        }
                    });
                } else {
                    error!("Terminal feature is disabled");
                }
            }
            _ => {}
        }
    }
}
