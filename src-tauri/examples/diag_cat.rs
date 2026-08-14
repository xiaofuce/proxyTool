//! 读取 /tmp/hc_dbg.log 全文 (helper dbg)
use std::sync::Arc;
use russh::client;
use tokio::io::AsyncReadExt;

const SERVER: &str = "203.0.113.20";
const USER: &str = "tester";
fn pass() -> &'static str {
    proxy_tool_lib::creds::pass()
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
    let mut session = client::connect(config, &format!("{SERVER}:22"), H).await.unwrap();
    let auth = session.authenticate_password(USER, pass()).await.unwrap();
    assert!(auth.success());
    let chan = session.channel_open_session().await.unwrap();
    chan.exec(true, "cat /tmp/hc_dbg.log 2>/dev/null | tail -600").await.unwrap();
    let mut stream = chan.into_stream();
    let mut out = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(30), stream.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    println!("{}", String::from_utf8_lossy(&out));
}
