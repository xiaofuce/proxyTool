//! 工具: 在测试服务器上执行任意命令 (凭据/端口来自 .test-creds.local)
//!
//! 用法: cargo run -p proxy-tool-core --example remote -- "ss -tln | head"
//! 常用于排查隧道端口/清理测试残留, 也可当 sshpass 平替。

use std::time::Duration;

use proxy_tool_core::creds;
use proxy_tool_core::known_hosts::KnownHosts;
use proxy_tool_core::ssh::{remote_exec, AuthMethod};

#[tokio::main]
async fn main() {
    let Some(cmd) = std::env::args().nth(1) else {
        eprintln!("用法: cargo run -p proxy-tool-core --example remote -- \"<命令>\"");
        std::process::exit(2);
    };
    let c = creds::load();
    println!("--> {}@{}:{} $ {}", c.user, c.server, c.port, cmd);
    let out = remote_exec(
        &c.server,
        c.port,
        &c.user,
        &AuthMethod::Password(c.pass.clone()),
        &cmd,
        Duration::from_secs(60),
        &KnownHosts::in_memory(),
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("执行失败: {e}");
        std::process::exit(1);
    });
    println!("{out}");
}
