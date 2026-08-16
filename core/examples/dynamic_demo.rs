//! 动态隧道 (-D) 实流量演示: 启动 SOCKS5 监听后保持运行, 供外部工具
//! (curl --socks5) 验证经服务器转发的真实外网 HTTP 通路。
//! 用法: cargo run -p proxy-tool-core --example dynamic_demo -- [listen_port]
//! 凭据读取: core/.test-creds.local 或环境变量 (见 creds.rs)。

use std::sync::Arc;

use proxy_tool_core::creds;
use proxy_tool_core::direct::{run_dynamic_forward, DirectConfig};
use proxy_tool_core::known_hosts::KnownHosts;
use proxy_tool_core::ssh::{AuthMethod, Logger};

#[tokio::main]
async fn main() {
    let listen_port: u16 = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(10888);
    let c = creds::load();
    let cfg = DirectConfig {
        server_host: c.server.clone(),
        server_port: c.port,
        username: c.user.clone(),
        auth: AuthMethod::Password(c.pass.clone()),
        listen_host: "127.0.0.1".into(),
        listen_port,
        keepalive: Default::default(),
        known_hosts: KnownHosts::in_memory(),
    };
    let logger: Logger = Arc::new(|msg: &str| println!("[tunnel] {msg}"));
    let (_session, _task) = run_dynamic_forward(cfg, logger)
        .await
        .expect("动态隧道建立失败");
    println!("READY socks5://127.0.0.1:{listen_port} 经 {} (退出 Ctrl+C)", c.server);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
