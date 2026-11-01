use crate::command_parser::LogLevel;
use crate::rustls_config::create_dangerous_config;
use log::Level;
use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async, connect_async_tls_with_config,
};
use url::{ParseError, Url};

pub fn init_logger(log_level: &LogLevel) {
    #[cfg(target_os = "windows")]
    simple_logger::set_up_windows_color_terminal();

    match log_level {
        LogLevel::Error => simple_logger::init_with_level(Level::Error).unwrap(),
        LogLevel::Warn => simple_logger::init_with_level(Level::Warn).unwrap(),
        LogLevel::Info => simple_logger::init_with_level(Level::Info).unwrap(),
        LogLevel::Debug => simple_logger::init_with_level(Level::Debug).unwrap(),
        LogLevel::Trace => simple_logger::init_with_level(Level::Trace).unwrap(),
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionUrls {
    pub basic_info: String,
    pub exec_callback: String,
    pub ws_terminal: String,
    pub ws_real_time: String,
}

impl Display for ConnectionUrls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Connection URLs:")?;
        writeln!(f, "  Basic Info URL: {}", self.basic_info)?;
        writeln!(f, "  Exec Callback URL: {}", self.exec_callback)?;
        writeln!(f, "  WebSocket Terminal URL: {}", self.ws_terminal)?;
        writeln!(f, "  WebSocket Real-time URL: {}", self.ws_real_time)
    }
}

pub fn build_urls(
    http_server: &str,
    ws_server: Option<&String>,
    token: &str,
) -> Result<ConnectionUrls, ParseError> {
    // 1. Construct http_url_base
    let http_url = Url::parse(http_server)?;
    let http_url_base = http_url.as_str().trim_end_matches('/');

    // 2. Construct ws_url_base
    let ws_url = if let Some(ws) = ws_server {
        Url::parse(ws)?
    } else {
        let mut ws_url = http_url.clone();
        match ws_url.scheme() {
            "http" => ws_url.set_scheme("ws").unwrap(),
            "https" => ws_url.set_scheme("wss").unwrap(),
            other => panic!("Unsupported scheme: {other}"),
        }
        ws_url
    };
    let ws_url_base = ws_url.as_str().trim_end_matches('/').to_string();

    // 3. Construct final URLs
    let basic_info_url = format!("{http_url_base}/api/clients/uploadBasicInfo?token={token}");
    let exec_callback_url = format!("{http_url_base}/api/clients/task/result?token={token}");
    let ws_terminal_url = format!("{ws_url_base}/api/clients/terminal?token={token}");
    let ws_real_time_url = format!("{ws_url_base}/api/clients/report?token={token}");

    let connection_urls = ConnectionUrls {
        basic_info: basic_info_url,
        exec_callback: exec_callback_url,
        ws_terminal: ws_terminal_url,
        ws_real_time: ws_real_time_url,
    };

    Ok(connection_urls)
}

pub async fn connect_ws(
    url: &str,
    tls: bool,
    skip_verify: bool,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, String> {
    let connection_timeout = Duration::from_secs(10);

    if tls {
        if skip_verify {
            timeout(
                connection_timeout,
                connect_async_tls_with_config(
                    url,
                    None,
                    false,
                    Some(Connector::Rustls(Arc::new(create_dangerous_config()))),
                ),
            )
            .await
            .map_err(|_| "WebSocket connection timeout".to_string())?
            .map(|ws| ws.0)
            .map_err(|e| format!("Failed to establish WebSocket connection: {e}"))
        } else {
            timeout(
                connection_timeout,
                connect_async_tls_with_config(url, None, false, None),
            )
            .await
            .map_err(|_| "WebSocket connection timeout".to_string())?
            .map(|ws| ws.0)
            .map_err(|e| format!("Failed to establish WebSocket connection: {e}"))
        }
    } else {
        timeout(connection_timeout, connect_async(url))
            .await
            .map_err(|_| "WebSocket connection timeout".to_string())?
            .map(|ws| ws.0)
            .map_err(|e| format!("Failed to establish WebSocket connection: {e}"))
    }
}

#[cfg(feature = "ureq-support")]
pub fn create_ureq_agent(disable_verification: bool) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .disable_verification(disable_verification)
                .build(),
        )
        .timeout_global(Some(Duration::from_secs(5)))
        .build();
    config.new_agent()
}

#[cfg(feature = "nyquest-support")]
pub fn create_nyquest_client(disable_verification: bool) -> nyquest::BlockingClient {
    use std::time::Duration;
    let mut client = nyquest::ClientBuilder::default()
        .request_timeout(Duration::from_secs(5))
        .user_agent("curl/8.7.1");
    if disable_verification {
        client = client.dangerously_ignore_certificate_errors();
    }
    client.build_blocking().unwrap()
}
