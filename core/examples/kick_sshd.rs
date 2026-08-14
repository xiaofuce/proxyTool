//! 临时工具: 重启服务器 sshd 以触发 SSH 隧道断开, 验证客户端自动重连。
//! 运行: cargo run --example kick_sshd
//! 验证完成后请删除本文件。
use russh::client;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

const SERVER: &str = "203.0.113.20";
const USER: &str = "tester";

fn pass() -> &'static str {
    proxy_tool_core::creds::pass()
}

struct H;
impl client::Handler for H {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _k: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::main]
async fn main() {
    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, &format!("{SERVER}:22"), H)
        .await
        .expect("连接服务器失败");
    assert!(
        session
            .authenticate_password(USER, pass())
            .await
            .unwrap()
            .success(),
        "SSH 认证失败"
    );
    let chan = session.channel_open_session().await.unwrap();
    // restart ssh 会重启 sshd, 断开所有 SSH 连接 (含本连接, 预期行为)。
    // sudo -S 从 stdin 读 sudo 密码 (与登录密码相同)。
    let cmd = format!("echo '{}' | sudo -S systemctl restart ssh 2>&1", pass());
    chan.exec(true, cmd).await.unwrap();
    let mut stream = chan.into_stream();
    let mut out = Vec::new();
    // sshd 重启会断开本连接, 超时/EOF 均属正常
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut out),
    )
    .await;
    print!("{}", String::from_utf8_lossy(&out));
    println!(">>> 已请求重启 sshd, 客户端应在 ~15s 内检测到断开并进入重连");
}
