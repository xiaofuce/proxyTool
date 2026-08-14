//! 诊断: 多连接失败时 helper 的视角 (独立 helper + dbg)
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
    let py = r#"
import socket,select,os,sys
def dbg(m):
 try:
  f=open("/tmp/hc_dbg.log","a"); f.write(m+"\n"); f.close()
 except Exception: pass
p=1083
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",p)); s.listen(8); dbg("bound "+str(p))
try:
 w=socket.socket(); w.settimeout(3); w.connect(("127.0.0.1",p))
 c2,a=s.accept(); c2.settimeout(3); w.send(b"X"); c2.recv(1)
 c2.close(); w.close(); dbg("warmup done")
except Exception as e: dbg("warmup EXC "+repr(e))
M=b"\x00\x00\x00\x08\xde\xad\xbe\xef\xde\xad\xbe\xef"
sys.stdout.buffer.write(M); sys.stdout.buffer.flush()
buf=b""; c=None; partial=None
def feed(d):
 global buf,c,partial
 buf+=d
 while True:
  if partial is not None:
   if len(buf)<4+partial: return
   if partial==8 and buf[4:12]==M[4:]:
    buf=buf[12:]; partial=None; continue
   if c is not None:
    try: c.sendall(buf[4:4+partial])
    except Exception as e: dbg("sendall EXC "+repr(e))
   buf=buf[4+partial:]; partial=None
  i=buf.find(M)
  if i<0:
   if len(buf)>len(M)-1: buf=buf[len(M)-1:]
   return
  buf=buf[i+len(M):]
  if len(buf)<4: return
  n=int.from_bytes(buf[:4],"big")
  if n==8 and buf[4:12]==M[4:]:
   buf=buf[12:]; continue
  if n==0:
   buf=buf[4:]
   if c is not None: c.close()
   c=None; dbg("feed_end")
   continue
  if len(buf)<4+n:
   partial=n; return
  if c is not None:
   try: c.sendall(buf[4:4+n])
   except Exception as e: dbg("sendall EXC "+repr(e))
  buf=buf[4+n:]
while True:
 r,_,_=select.select([s,sys.stdin],[],[],0.5)
 if sys.stdin in r:
  d=os.read(0,65536)
  if not d: dbg("stdin EOF"); sys.exit(0)
  dbg("stdin "+str(len(d)))
  feed(d)
  continue
 if s in r:
  c,a=s.accept(); dbg("accept "+str(a))
  sys.stdout.buffer.write(M); sys.stdout.buffer.flush()
  try:
   while True:
    r,_,_=select.select([c,sys.stdin],[],[],0.3)
    if sys.stdin in r:
     d=os.read(0,65536)
     if not d: sys.exit(0)
     feed(d)
     if c is None: break
    if c in r:
     d=c.recv(65536)
     if not d:
      dbg("ceof")
      sys.stdout.buffer.write(M+b"\x00\x00\x00\x00")
      sys.stdout.buffer.flush()
      break
     dbg("cread "+str(len(d))+" "+d[:8].hex())
     sys.stdout.buffer.write(M+len(d).to_bytes(4,"big")+d)
     sys.stdout.buffer.flush()
  except Exception as e:
   dbg("loop EXC "+repr(e))
  if c is not None: c.close()
  c=None
"#;
    let cmd = format!(
        "exec 2>&1; rm -f /tmp/hc_dbg.log; pkill -f 'socket,select,os,sys' 2>/dev/null; sleep 0.5; nohup python3 -c '{}' 1083 >/dev/null 2>&1 < /dev/null & sleep 1; python3 - <<'PYEOF'
import socket
ok=0
for i in range(5):
 data=bytes((i*37+j)%256 for j in range(8192))
 try:
  s=socket.create_connection((\"127.0.0.1\",1083),timeout=8)
  s.settimeout(8)
  s.sendall(data)
  recv=b\"\"
  while len(recv)<len(data):
   d=s.recv(65536)
   if not d: break
   recv+=d
  s.close()
  print(\"conn\",i,\"OK\" if recv==data else \"MISMATCH\",len(recv))
  ok+=1
 except Exception as e:
  print(\"conn\",i,\"EXC\",repr(e))
print(\"TOTAL_OK\",ok,\"/5\")
PYEOF
sleep 1; echo '--- dbg ---'; cat /tmp/hc_dbg.log; echo '--- helper 进程 ---'; ps aux | grep '[p]ython3 -c' | head -2; echo '--- 1083 ---'; ss -tln | grep :1083 || echo none",
        py.replace('\'', "\'")
    );
    chan.exec(true, cmd.as_str()).await.unwrap();
    let mut stream = chan.into_stream();
    let mut out = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(90), stream.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    println!("{}", String::from_utf8_lossy(&out));
}
