//! 远程诊断: 1081 占用 + 手动运行 helper 观察输出
//! 运行: cargo run --example diag_helper
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
    let mut session = client::connect(config, &format!("{SERVER}:22"), H)
        .await
        .unwrap();
    let auth = session.authenticate_password(USER, pass()).await.unwrap();
    assert!(auth.success());
    let chan = session.channel_open_session().await.unwrap();
    // 用原始字符串避免转义地狱; bash 里用双引号包裹 python -c, 脚本内用双引号字符串
    let py = r#"
import socket,select,os,sys
p=1081
s=socket.socket()
print("BIND...", flush=True)
try:
 s.bind(("127.0.0.1",p))
 s.listen(8)
 print("BOUND", flush=True)
except Exception as e:
 print("BIND_FAIL "+repr(e), flush=True)
 sys.exit(9)
w=socket.socket(); w.settimeout(3)
try:
 w.connect(("127.0.0.1",p))
 c2,a=s.accept(); c2.settimeout(3)
 w.send(b"X"); c2.recv(1)
 c2.close(); w.close()
 print("WARMUP_DONE", flush=True)
except Exception as e:
 print("WARMUP_FAIL "+repr(e), flush=True)
M=b"\x00\x00\x00\x08\xde\xad\xbe\xef\xde\xad\xbe\xef"
sys.stdout.buffer.write(M); sys.stdout.buffer.flush()
while True:
 r,_,_=select.select([s,sys.stdin],[],[],1)
 if sys.stdin in r:
  d=os.read(0,65536)
  if not d: print("STDIN_EOF", flush=True); sys.exit(0)
  print("GOT_STDIN "+str(len(d)), flush=True)
 if s in r:
  c,a=s.accept(); print("ACCEPT "+str(a), flush=True)
  c.close(); print("CLOSED", flush=True)
"#;
    let cmd = format!(
        "exec 2>&1; echo '=== 占用检查 ==='; ss -tlnp | grep :1081 || echo '1081 空闲'; ps aux | grep '[p]ython3 -c' || echo '无 helper 进程'; echo '=== 手动运行 helper ==='; timeout 8 python3 -c '{}' 2>&1; echo EXIT=$?",
        // 脚本里不能有单引号 (bash 双引号内可以, 但 python -c 用单引号包裹)
        py.replace('\'', "\\'")
    );
    chan.exec(true, cmd.as_str()).await.unwrap();
    let mut stream = chan.into_stream();
    let mut out = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(30), stream.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    println!("{}", String::from_utf8_lossy(&out));
}
