//! 端到端验收测试 (M1): 连接真实测试服务器, 建立反向隧道, 验证服务器能经隧道访问外网
//!
//! 链路: 服务器 curl --socks5h--> 127.0.0.1:1081 (服务器监听)
//!        --SSH反向通道--> 本机 --TCP--> 内置SOCKS5 (127.0.0.1:<port>)
//!        --系统路由(经VPN)--> 外网
//!
//! 前提: 本地 VPN 已开启 (如 v2cloud TUN 模式)。
//! 运行: cargo test --test e2e_tunnel -- --nocapture
//! 说明: 服务器位于大陆机房, 直连 google 通常被墙; 经隧道访问应返回 200,
//!       以此证明流量确实走 VPN 出口而非服务器自身网络。
//!
//! 已知情况: 测试服务器 (腾讯云) 装有主机安全组件 libonion (经 /etc/ld.so.preload
//! 注入 sshd), 会向 forwarded-tcpip 通道注入审计数据。run_tunnel 会自动探测并
//! 切换到兼容模式 (session 通道 + python3 桥接助手), 本文件两个测试分别验证
//! 兼容模式数据通路与自动切换后的完整外网访问。

use std::sync::Arc;
use std::time::Duration;

use proxy_tool_core::socks::start_socks_server;
use proxy_tool_core::transport::python_bridge;
use proxy_tool_core::tunnel::{run_tunnel, Logger, TunnelConfig};
use russh::client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SERVER: &str = "203.0.113.20";
const USER: &str = "tester";
fn pass() -> &'static str {
    proxy_tool_core::creds::pass()
}

/// 把 russh 的 log 输出到 stdout
struct TestLogger;
impl log::Log for TestLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().starts_with("russh")
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!("[{}] {}", record.target(), record.args());
        }
    }
    fn flush(&self) {}
}
static LOGGER: TestLogger = TestLogger;
fn init_logger() {
    let _ = log::set_logger(&LOGGER).map(|_| log::set_max_level(log::LevelFilter::Trace));
}

/// 用于执行远程命令的独立 SSH 连接 (与隧道连接分离, 测试驱动用)
struct ExecHandler;
impl client::Handler for ExecHandler {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _k: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn connect_exec_handle() -> Arc<tokio::sync::Mutex<client::Handle<ExecHandler>>> {
    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, &format!("{SERVER}:22"), ExecHandler)
        .await
        .expect("exec 连接失败");
    let auth = session
        .authenticate_password(USER, pass())
        .await
        .expect("exec 认证失败");
    assert!(auth.success(), "exec 密码认证被拒绝");
    Arc::new(tokio::sync::Mutex::new(session))
}

/// 在服务器上执行命令 (经独立连接), 自定义超时
async fn exec_timeout(
    handle: &Arc<tokio::sync::Mutex<client::Handle<ExecHandler>>>,
    cmd: &str,
    timeout: Duration,
) -> String {
    let chan = handle
        .lock()
        .await
        .channel_open_session()
        .await
        .expect("打开 session 通道");
    chan.exec(true, cmd).await.expect("发送 exec 请求");
    let mut stream = chan.into_stream();
    let mut out = String::new();
    tokio::time::timeout(timeout, stream.read_to_string(&mut out))
        .await
        .expect("读取命令输出超时")
        .expect("读取命令输出失败");
    out
}

/// 在服务器上执行命令 (经独立连接), 返回 stdout (30s 超时, 快命令/诊断用)
async fn exec(handle: &Arc<tokio::sync::Mutex<client::Handle<ExecHandler>>>, cmd: &str) -> String {
    exec_timeout(handle, cmd, Duration::from_secs(30)).await
}

/// 诊断用: 执行命令但不因超时 panic, 返回 (已有输出, 是否超时)
async fn exec_partial(
    handle: &Arc<tokio::sync::Mutex<client::Handle<ExecHandler>>>,
    cmd: &str,
) -> (String, bool) {
    let chan = handle
        .lock()
        .await
        .channel_open_session()
        .await
        .expect("打开 session 通道");
    chan.exec(true, cmd).await.expect("发送 exec 请求");
    let mut stream = chan.into_stream();
    let mut out = String::new();
    let timed_out = tokio::time::timeout(Duration::from_secs(40), stream.read_to_string(&mut out))
        .await
        .is_err();
    (out, timed_out)
}

/// 纯 Rust SOCKS5 客户端: 经 127.0.0.1:<port> 代理访问 www.google.com:80,
/// 返回首个 HTTP 响应行 (排除外部 curl/防火墙变量)
async fn verify_socks_local(port: u16) -> Result<String, String> {
    use tokio::net::TcpStream;
    let mut s = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| format!("连接 SOCKS 失败: {e}"))?;
    // 握手: 无认证
    s.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| format!("写握手失败: {e}"))?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)
        .await
        .map_err(|e| format!("读握手回复失败: {e}"))?;
    if r != [0x05, 0x00] {
        return Err(format!("握手回复异常: {r:02x?}"));
    }
    // 请求: CONNECT www.google.com:80
    let domain = b"www.google.com";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain);
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req)
        .await
        .map_err(|e| format!("写请求失败: {e}"))?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep)
        .await
        .map_err(|e| format!("读 CONNECT 回复失败: {e}"))?;
    if rep[1] != 0x00 {
        return Err(format!("CONNECT 被拒: {:02x?}", &rep[..2]));
    }
    // 发 HTTP 请求, 读响应行
    s.write_all(b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| format!("写 HTTP 失败: {e}"))?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)
        .await
        .map_err(|e| format!("读 HTTP 响应失败: {e}"))?;
    Ok(String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or("NO_RESPONSE")
        .to_string())
}

/// 本地 echo 服务器: 收到什么原样写回
async fn start_echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let echo_port = listener.local_addr().unwrap().port();
    println!("== echo 服务器: 127.0.0.1:{echo_port}");
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    echo_port
}

/// 诊断并清理服务器端残留的 helper 进程与端口占用
#[tokio::test]
async fn server_cleanup_diag() {
    init_logger();
    let exec_h = connect_exec_handle().await;
    let cmd = "exec 2>&1
echo '=== python3 进程 ==='
ps aux | grep '[p]ython3' || echo 'python3: none'
echo '=== 1081/1082 监听 ==='
ss -tlnp | grep -E ':1081|:1082' || echo 'ports: none'
echo '=== sshd 转发会话 ==='
ss -tnp | grep -E ':1081|:1082' || echo 'estab: none'
echo '=== 清理 ==='
pkill -f helper_test 2>/dev/null
pkill -f 'socket,select,os,sys' 2>/dev/null
sleep 1
echo '=== 清理后 ==='
ps aux | grep '[p]ython3' || echo 'python3: none'
ss -tlnp | grep -E ':1081|:1082' || echo 'ports: none'";
    let out = exec(&exec_h, cmd).await;
    println!("--- 残留诊断 ---\n{out}");
}

/// 服务器端手动验证 python 桥接助手: 预热吸收 + 每进程/每连接注入判定
#[tokio::test]
async fn helper_manual_probe() {
    init_logger();
    let exec_h = connect_exec_handle().await;
    let cmd = "exec 2>&1
rm -f /tmp/helper_dbg.log /tmp/helper_stdout.log /tmp/h_in
mkfifo /tmp/h_in 2>/dev/null
exec 9<>/tmp/h_in
cat > /tmp/helper_test.py <<'PYEOF'
import socket,select,os,sys
def dbg(m):
 try:
  f=open(\"/tmp/helper_dbg.log\",\"a\"); f.write(m+\"\\n\"); f.close()
 except Exception: pass
p=int(sys.argv[1])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((\"127.0.0.1\",p)); s.listen(8); dbg(\"bound\")
try:
 w=socket.socket(); w.connect((\"127.0.0.1\",p)); dbg(\"warmup connected\")
 c2,a=s.accept(); dbg(\"warmup accepted \"+str(a))
 w.send(b\"X\"); dbg(\"warmup sent\")
 d=c2.recv(1); dbg(\"warmup recv1 len=\"+str(len(d)))
 c2.close(); w.close(); dbg(\"warmup done\")
except Exception as e:
 dbg(\"warmup EXC \"+repr(e))
while True:
 c,a=s.accept(); dbg(\"ACCEPT \"+str(a))
 try:
  while True:
   r,_,_=select.select([c,sys.stdin],[],[],0.3)
   if sys.stdin in r:
    d=os.read(0,65536)
    if not d: dbg(\"stdin EOF\"); sys.exit(0)
    dbg(\"stdin->send \"+str(len(d)))
    c.sendall(d)
   if c in r:
    d=c.recv(65536)
    if not d: dbg(\"client EOF\"); break
    dbg(\"client->stdout \"+str(len(d)))
    sys.stdout.buffer.write(d); sys.stdout.buffer.flush()
 except Exception as e:
  dbg(\"loop EXC \"+repr(e))
 c.close(); dbg(\"closed\")
PYEOF
python3 /tmp/helper_test.py 1084 > /tmp/helper_stdout.log 2>&1 < /tmp/h_in &
sleep 1
exec 3<>/dev/tcp/127.0.0.1/1084 && echo CONNECT_OK || echo CONNECT_FAIL
echo HELLO1 >&3        # bash 写 (write(2) 路径) -> 对照: 预期注入
sleep 8
echo \"S_bash=\"$(wc -c < /tmp/helper_stdout.log)
head -c 16 /tmp/helper_stdout.log | od -An -tx1
exec 3>&-
sleep 1
echo \"=== 阶段2: curl 写 (send 路径) 判定注入 ===\"
timeout 8 curl -s -o /dev/null --connect-timeout 3 -x socks5h://127.0.0.1:1084 http://10.255.255.1/ 2>/dev/null
sleep 5
echo \"S_curl=\"$(wc -c < /tmp/helper_stdout.log)
echo \"--- curl 数据头部 (S_bash 偏移后, 找 05 01 00 握手) ---\"
od -An -tx1 -j 1761 -N 64 /tmp/helper_stdout.log
echo \"--- dbg ---\"; cat /tmp/helper_dbg.log
exec 9>&-
kill %1 2>/dev/null; wait 2>/dev/null";
    let out = exec(&exec_h, cmd).await;
    println!("--- 手动 helper 测试 ---\n{out}");
}

/// 兼容模式数据通路测试: 100KB 数据经会话通道隧道往返, 验证无损
/// (字节模式用 python3 生成, 规避 mawk printf %c 在 UTF-8 locale 下的多字节输出)
#[tokio::test]
async fn session_mode_passes_large_data() {
    init_logger();
    let echo_port = start_echo_server().await;

    let cfg = TunnelConfig {
        server_host: SERVER.into(),
        server_port: 22,
        username: USER.into(),
        password: pass().into(),
        remote_port: 1082,
        local_proxy_host: "127.0.0.1".into(),
        local_proxy_port: echo_port,
        keepalive: Default::default(),
    };
    let logger: Logger = Arc::new(|msg| println!("[tunnel] {msg}"));
    let (_tunnel, _bound) = python_bridge::establish(cfg, logger)
        .await
        .expect("兼容模式隧道建立失败");
    let exec_h = connect_exec_handle().await;

    // 服务器上确认转发助手监听与进程
    let diag = exec(
        &exec_h,
        "ss -tln | grep :1082; ps aux | grep -c '[p]ython3'",
    )
    .await;
    println!("--- 服务器诊断 ---\n{diag}");

    // 服务器端: 发 100KB 字节模式到 1082, 收回并比对。
    // 注意: 不用 bash /dev/tcp (write(2) 路径会被 libonion 注入命令历史转储),
    // 用 python socket (send 路径, 与 curl 相同, 产品场景无注入)。
    let cmd = "exec 2>&1
echo STEP1
python3 - <<'PYEOF'
import socket
data=bytes(i%256 for i in range(102400))
s=socket.create_connection((\"127.0.0.1\",1082),timeout=20)
s.settimeout(20)
s.sendall(data)
print(\"STEP2_SENT\",len(data))
recv=b\"\"
while len(recv)<len(data):
 d=s.recv(65536)
 if not d: break
 recv+=d
s.close()
print(\"STEP3_RECV\",len(recv))
open(\"/tmp/echosend.bin\",\"wb\").write(data)
open(\"/tmp/echorecv.bin\",\"wb\").write(recv)
print(\"ECHO_OK\" if recv==data else \"ECHO_MISMATCH\")
PYEOF
wc -c /tmp/echosend.bin /tmp/echorecv.bin";
    let out = exec(&exec_h, cmd).await;
    println!("--- echo 测试 ---\n{out}");
    assert!(
        out.contains("ECHO_OK"),
        "100KB 隧道回环失败, 实际输出: {out}"
    );
    println!("== 兼容模式数据通路验证通过: 100KB 经隧道无损往返");
}

/// 兼容模式多连接测试: 服务器连续 5 次经隧道连接, 每次 8KB 往返无损。
/// 验证跨连接的帧边界/End 帧处理 (v2cloud 代理自身不稳, 故用 echo 服务器)
#[tokio::test]
async fn session_mode_multi_conn() {
    init_logger();
    let echo_port = start_echo_server().await;

    let cfg = TunnelConfig {
        server_host: SERVER.into(),
        server_port: 22,
        username: USER.into(),
        password: pass().into(),
        remote_port: 1082,
        local_proxy_host: "127.0.0.1".into(),
        local_proxy_port: echo_port,
        keepalive: Default::default(),
    };
    let logger: Logger = Arc::new(|msg| println!("[tunnel] {msg}"));
    let (_tunnel, _bound) = python_bridge::establish(cfg, logger)
        .await
        .expect("兼容模式隧道建立失败");
    let exec_h = connect_exec_handle().await;

    let cmd = "exec 2>&1
rm -f /tmp/hc_dbg.log
python3 -u - <<'PYEOF'
import socket
ok=0
for i in range(5):
 data=bytes((i*37+j)%256 for j in range(8192))
 try:
  s=socket.create_connection((\"127.0.0.1\",1082),timeout=15)
  s.settimeout(15)
  print(\"conn\",i,\"srcport\",s.getsockname()[1])
  s.sendall(data)
  recv=b\"\"
  while len(recv)<len(data):
   d=s.recv(65536)
   if not d: break
   recv+=d
  s.close()
  if recv==data: ok+=1
  print(\"conn\",i,\"OK\" if recv==data else \"MISMATCH\",len(recv))
 except Exception as e:
  print(\"conn\",i,\"EXC\",repr(e))
print(\"TOTAL_OK\",ok,\"/5\")
PYEOF";
    let (out, timed_out) = exec_partial(&exec_h, cmd).await;
    println!("--- 多连接 echo 测试 (超时={timed_out}) ---\n{out}");
    let dbg = exec(
        &exec_h,
        "echo '=== HELPER DBG ==='; tail -200 /tmp/hc_dbg.log 2>/dev/null",
    )
    .await;
    println!("{dbg}");
    assert!(
        out.contains("TOTAL_OK 5 /5"),
        "多连接隧道回环失败, 实际输出: {out}"
    );
    println!("== 兼容模式多连接验证通过: 5 连接无损往返");
}

/// 诊断: 标准模式下服务器 curl 连接 1081 为何未被转发到本机
/// (监听显示 [::1]:1081 IPv6, curl 连 127.0.0.1 — 验证 IPv4/IPv6 映射与 sshd 行为)
#[tokio::test]
async fn std_mode_diag() {
    init_logger();
    use proxy_tool_core::probe::probe_local_proxy;
    let found = probe_local_proxy().await;
    let port = found
        .iter()
        .find(|r| r.socks5_confirmed)
        .map(|r| r.port)
        .expect("未探测到 VPN SOCKS 端口");
    println!("== 复用 VPN SOCKS 端口: {port}");

    // 清理残留 helper (上轮测试可能残留进程占住 1081)
    let exec_h0 = connect_exec_handle().await;
    let clean = exec(
        &exec_h0,
        "pkill -f 'socket,select,os,sys' 2>/dev/null; sleep 1; ss -tln | grep :1081 && echo PORT_BUSY || echo PORT_FREE",
    )
    .await;
    println!("--- 端口清理 ---\n{clean}");

    let cfg = TunnelConfig {
        server_host: SERVER.into(),
        server_port: 22,
        username: USER.into(),
        password: pass().into(),
        remote_port: 1081,
        local_proxy_host: "127.0.0.1".into(),
        local_proxy_port: port,
        keepalive: Default::default(),
    };
    let logger: Logger = Arc::new(|msg| println!("[tunnel] {msg}"));
    let ((_tunnel, _c), _bound) = run_tunnel(cfg, logger).await.expect("隧道建立失败");
    let exec_h = connect_exec_handle().await;

    let cmd = "exec 2>&1
echo '=== python3 残留进程 ==='
ps aux | grep '[p]ython3' || echo 'none'
echo '=== bindv6only ==='
cat /proc/sys/net/ipv6/bindv6only
echo '=== 监听状态 ==='
ss -tlnp | grep :1081
echo '=== 纯 TCP 连接测试 (bash) ==='
timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/1081 && echo TCP_127_OK || echo TCP_127_FAIL'
timeout 5 bash -c 'exec 3<>/dev/tcp/[::1]/1081 && echo TCP_V6_OK || echo TCP_V6_FAIL'
echo '=== curl -v 详细 (socks5h) ==='
timeout 25 curl -v --connect-timeout 5 -x socks5h://127.0.0.1:1081 https://www.google.com -o /dev/null 2>&1 | grep -E 'Connected|Refused|failed|SOCKS|error|Hello|HTTP|Trying|Connection' | head -20
echo '=== curl -v 详细 (socks5 127.0.0.1) ==='
timeout 25 curl -v --connect-timeout 5 -x socks5://127.0.0.1:1081 http://www.google.com -o /dev/null 2>&1 | grep -E 'Connected|Refused|failed|SOCKS|error|Trying|Connection' | head -20
echo '=== 测试后监听 ==='
ss -tlnp | grep :1081";
    let out = exec(&exec_h, cmd).await;
    println!("--- 标准模式诊断 ---\n{out}");
    tokio::time::sleep(Duration::from_secs(5)).await; // 等待本机日志刷出
}

/// M1 验收: run_tunnel 自动探测污染并切换兼容模式, 服务器经隧道访问 google 返回 200
#[tokio::test]
async fn server_can_reach_internet_through_tunnel() {
    // 1. 走真实产品路径: 探测本机 VPN SOCKS 端口并复用 (resolve_local_proxy 的逻辑);
    //    探测不到时才启动内置 SOCKS 兜底。
    //    注意: 内置 SOCKS 直连出口需要系统路由经 VPN (TUN 模式); 本测试服务器用的
    //    v2cloud 是端口模式, 系统路由未接管, 故必须探测到 7892 才能出网。
    use proxy_tool_core::probe::probe_local_proxy;
    let found = probe_local_proxy().await;
    let vpn_port = found.iter().find(|r| r.socks5_confirmed).map(|r| r.port);
    println!("== 探测到的代理端口: {found:?}");
    let (local_port, builtin) = match vpn_port {
        Some(p) => {
            println!("== 复用 VPN 自带 SOCKS 端口: {p}");
            (p, None)
        }
        None => {
            let s = start_socks_server(47892)
                .await
                .expect("启动内置 SOCKS 服务器");
            println!("== 未探测到 VPN 端口, 使用内置 SOCKS: {}", s.port);
            (s.port, Some(s))
        }
    };

    // 2. 建立反向隧道 (真实代码路径, 自动选择模式)
    let cfg = TunnelConfig {
        server_host: SERVER.into(),
        server_port: 22,
        username: USER.into(),
        password: pass().into(),
        remote_port: 1081,
        local_proxy_host: "127.0.0.1".into(),
        local_proxy_port: local_port,
        keepalive: Default::default(),
    };
    let logger: Logger = Arc::new(|msg| println!("[tunnel] {msg}"));
    let ((_tunnel, _corrupted), _bound) = run_tunnel(cfg, logger).await.expect("隧道建立失败");
    println!("== 隧道建立成功");
    let exec_h = connect_exec_handle().await;

    // 2.5 本机直接验证内置 SOCKS (不经隧道, 排除隧道因素) — 纯 Rust SOCKS5 客户端
    let v = tokio::time::timeout(Duration::from_secs(15), verify_socks_local(local_port)).await;
    println!("--- 本机经内置 SOCKS 访问 google (Rust 客户端): {v:?} ---");

    // 3. 服务器上确认 1081 正在监听
    let out = exec(&exec_h, "ss -tln | grep :1081 || echo '(1081 未监听!)'").await;
    println!("--- 服务器 1081 监听状态 ---\n{out}");

    // 4. 对照: 不走隧道直连 google (大陆服务器预期被墙, 仅诊断信息, 不判定)
    let direct = exec(
        &exec_h,
        "curl -s -o /dev/null --connect-timeout 6 -w '%{http_code}' https://www.google.com || echo FAIL",
    )
    .await;
    println!("--- 直连 google (对照, 预期非200) ---\n{direct}");

    // 5. 核心断言: 经隧道访问 google (跟随重定向; google 常先返回 302 地区跳转)
    let heads = exec(
        &exec_h,
        "curl -s -o /dev/null -D - --connect-timeout 20 -x socks5h://127.0.0.1:1081 https://www.google.com || echo CURL_FAIL",
    )
    .await;
    println!("--- 经隧道访问 google 响应头 ---\n{heads}");
    let again = exec(
        &exec_h,
        "echo '=== helper 进程 ==='; ps aux | grep '[p]ython3 -c' | head -2
echo '=== 1081 连接 ==='; ss -tn | grep :1081 || echo none
echo '=== curl 详细 (第二个请求) ==='
timeout 25 curl -v --connect-timeout 5 -x socks5h://127.0.0.1:1081 https://www.google.com -o /dev/null 2>&1 | head -25 || echo AGAIN_FAIL",
    )
    .await;
    println!("--- 第二个独立请求 ---\n{again}");
    // 注 1: 本地 VPN (v2cloud 端口模式) 的 7892 端口自身不稳定 (本机直连亦复现:
    // 连续访问 https google 前两次失败第三次成功), 故对目标请求做重试。
    // 重试循环最坏 5×(30+2)s, exec 超时须与之匹配 (曾因 30s 硬超时在 VPN
    // 低迷期截断重试循环, 误报隧道失败)。隧道本身的多连接无损性由
    // session_mode_multi_conn 验证。
    // 注 2: 判定标准 = 拿到真实 HTTP 状态码 (非 000)。google 对 VPN 出口 IP
    // 常做地区重定向 (302 → google.com.hk), 重定向链有时止步于 302 ——
    // 本机直经 VPN 亦复现, 与隧道无关; 任何非 000 状态码都证明
    // 服务器 → 隧道 → 本机 VPN → google 的完整链路 (TCP+TLS+HTTP) 可用。
    let via = exec_timeout(
        &exec_h,
        "for i in 1 2 3 4 5; do
  code=$(curl -sL -o /dev/null --connect-timeout 20 --max-time 30 -x socks5h://127.0.0.1:1081 -w '%{http_code}' https://www.google.com)
  echo \"尝试 $i: $code\"
  if [ \"$code\" != 000 ] && [ -n \"$code\" ]; then echo VIA_OK; break; fi
  sleep 2
done",
        Duration::from_secs(200),
    )
    .await;
    println!("--- 经隧道访问 google (跟随重定向, 最多5次) ---\n{via}");

    assert!(
        via.contains("VIA_OK"),
        "经隧道访问 google 失败 (若本地 VPN 未开启也可能失败), 实际输出: {via}"
    );
    println!("== 验收通过: 服务器经本机 VPN 隧道成功访问外网");

    // 6. 清理 (若启动了内置 SOCKS)
    if let Some(s) = builtin {
        s.stop();
    }
}

/// 断开机制验证: russh Handle::disconnect() 发送 DISCONNECT 消息后,
/// is_closed() 应变为 true (GUI「断开」按钮依赖此机制真正关闭连接)。
/// 旧 bug: 仅 drop Arc 引用无效 (start_tunnel 后台任务持有 clone)。
#[tokio::test]
async fn disconnect_closes_session() {
    init_logger();
    let echo_port = start_echo_server().await;

    let cfg = TunnelConfig {
        server_host: SERVER.into(),
        server_port: 22,
        username: USER.into(),
        password: pass().into(),
        remote_port: 1083,
        local_proxy_host: "127.0.0.1".into(),
        local_proxy_port: echo_port,
        keepalive: Default::default(),
    };
    let logger: Logger = Arc::new(|msg| println!("[tunnel] {msg}"));
    let ((session, _corrupted), _bound) = run_tunnel(cfg, logger).await.expect("隧道建立失败");

    // 确认连接建立时 is_closed() = false
    assert!(
        !session.lock().await.is_closed(),
        "新建立的会话不应处于已关闭状态"
    );
    println!("== 会话已建立, is_closed = false");

    // 模拟 disconnect_tunnel 命令: 发送 SSH DISCONNECT 消息
    {
        let h = session.lock().await;
        let r = h
            .disconnect(russh::Disconnect::ByApplication, "user disconnect", "")
            .await;
        println!("== disconnect() 结果: {r:?}");
        drop(h);
    }

    // 等待连接真正关闭 (russh 消息循环处理 DISCONNECT 后 sender 关闭)
    let closed = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if session.lock().await.is_closed() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        closed,
        "disconnect() 后 is_closed() 未在 15s 内变为 true (断开机制失效)"
    );
    println!("== 断开机制验证通过: DISCONNECT 后 is_closed = true");

    // 服务器侧确认 1083 监听已消失 (helper 随 SSH 连接关闭退出)
    let exec_h = connect_exec_handle().await;
    let diag = exec(
        &exec_h,
        "sleep 2; ss -tln | grep :1083 && echo STILL_LISTENING || echo PORT_FREED",
    )
    .await;
    println!("--- 断开后服务器 1083 状态 ---\n{diag}");
    assert!(
        diag.contains("PORT_FREED"),
        "断开后服务器 1083 端口应被释放, 实际: {diag}"
    );
    println!("== 服务器侧确认: 隧道端口已释放");
}

/// -R 端口 0 (P4): 服务器动态分配实际端口 (标准模式 = tcpip_forward 回告值,
/// 兼容模式 = 助手 PORT 行上报), run_tunnel 返回实际端口且数据通路完整往返。
/// 本服务器 (libonion 注入) 会先走标准模式失败再回退兼容模式 —— 覆盖
/// 兼容模式的 PORT 行协议 (标记帧前的新首写)。
#[tokio::test]
async fn port_zero_dynamic_allocation() {
    init_logger();
    let echo_port = start_echo_server().await;

    let cfg = TunnelConfig {
        server_host: SERVER.into(),
        server_port: 22,
        username: USER.into(),
        password: pass().into(),
        remote_port: 0, // 动态分配
        local_proxy_host: "127.0.0.1".into(),
        local_proxy_port: echo_port,
        keepalive: Default::default(),
    };
    let logger: Logger = Arc::new(|msg| println!("[tunnel] {msg}"));
    let ((_session, _c), bound) = run_tunnel(cfg, logger).await.expect("端口 0 隧道建立失败");
    assert!(bound != 0, "动态分配的端口不应为 0");
    println!("== 动态分配端口: {bound}");

    // 服务器上经分配端口连接 → 写标志串 → 读回 echo (完整数据往返)。
    // 用 python socket 而非 bash /dev/tcp: bash 的 write(2) 路径会被 libonion
    // 注入审计数据 (见 session_mode_passes_large_data 同款注释), python 的
    // send 路径与 curl 一致, 产品场景无注入。
    let exec_h = connect_exec_handle().await;
    let cmd = format!(
        "exec 2>&1
python3 - <<'PYEOF'
import socket
s=socket.create_connection((\"127.0.0.1\",{bound}),timeout=20)
s.settimeout(20)
s.sendall(b\"HELLO_PORT0\")
d=b\"\"
while len(d)<10:
 x=s.recv(65536)
 if not x: break
 d+=x
s.close()
print(\"ECHO_OK\" if d==b\"HELLO_PORT0\" else \"ECHO_MISMATCH \"+repr(d[:48]))
PYEOF
ss -tln | grep ':{bound} ' || echo NO_LISTEN"
    );
    let out = exec_timeout(&exec_h, &cmd, Duration::from_secs(40)).await;
    println!("--- 端口 0 通路 ---\n{out}");
    assert!(
        out.contains("ECHO_OK"),
        "数据应经动态分配端口完整往返 (echo): {out}"
    );
    assert!(!out.contains("NO_LISTEN"), "服务器应在分配端口监听: {out}");
    println!("== 端口 0 动态分配验证通过");
}
