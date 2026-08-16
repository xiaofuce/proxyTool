//! 兼容模式传输: 会话通道 + 服务器端 python3 stdio 桥接助手 (帧复用单通道)
//!
//! 云主机安全组件 (libonion) 注入 sshd 的 forwarded-tcpip 通道时 (标准模式
//! 不可用/被污染, 见 russh_direct), 经 exec 在服务器上启动 python3 助手:
//! 助手监听 127.0.0.1:remote_port 并把每个连接接到 SSH 会话通道的
//! stdin/stdout, 本机把会话通道桥接到本地 SOCKS。语义等价 ssh -R, 但数据
//! 走会话通道 (不受注入影响)。服务器需有 python3 (主流发行版默认自带)。
//!
//! 帧协议 (标记帧/CRC32/分块/注入同步) 见 `frame`; 本文件 = 通道 IO 编排
//! (reader 任务 / 转发循环) + 服务器侧 python3 对称实现 (HELPER_PY)。

use std::sync::atomic::Ordering;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::model::TunnelError;
use crate::ssh::Logger;
use crate::transport::frame::{self, Frame, FrameParser};
use crate::transport::shared::{self, SharedState};
use crate::tunnel::{TunnelConfig, TunnelSession};

/// 兼容模式会话: helper 通道两个后台任务的句柄 (租约拆除用)。
/// abort 任务 -> 通道两半随任务结束 drop (ChannelCloseOnDrop -> CHANNEL_CLOSE)
/// -> helper stdin EOF 自行退出。Clone 浅共享 (槽内会话/轮询循环各持一份,
/// abort 幂等)。
#[derive(Clone)]
pub(crate) struct CompatSession {
    pub(crate) reader: tokio::task::AbortHandle,
    pub(crate) forwarder: tokio::task::AbortHandle,
}

impl CompatSession {
    /// 拆除本隧道的兼容模式 (不动所在连接): abort 后台任务即可,
    /// 通道计数由内置的收尾任务在两任务结束后递减。
    pub(crate) fn stop(self) {
        self.forwarder.abort();
        self.reader.abort();
    }
}

/// 兼容模式建立: 新 SSH 连接 + 会话通道桥接任务。
/// 污染标记恒 false —— 会话通道不经 sshd 转发路径, 无注入问题。
/// 返回 (会话, 服务器实际监听端口): `remote_port=0` 时助手动态分配端口,
/// 启动后经通道上报一行 `PORT <n>` (首条 stdout 写入, 无注入前史, 必然干净;
/// 显式端口路径保持原协议不变, 不读该行)。
pub async fn establish(
    cfg: TunnelConfig,
    logger: Logger,
) -> Result<(TunnelSession, u16), TunnelError> {
    let state = shared::connect(
        &cfg.server_host,
        cfg.server_port,
        &cfg.username,
        &cfg.auth,
        cfg.keepalive,
        &cfg.known_hosts,
        shared::DEFAULT_MAX_SESSIONS,
        &logger,
    )
    .await?;
    // CompatSession 任务常驻到通道关闭 (与旧行为一致), 句柄不需要上抛
    let (_compat, bound_port) = open_helper(&state, &cfg, logger).await?;
    Ok(((state.handle, state.corrupted), bound_port))
}

/// 在**已有**连接上启动兼容模式: 开 helper 会话通道 + 帧读取/转发任务。
/// 共享连接的复用入口 (专用连接走 establish 同路)。
pub(crate) async fn open_helper(
    state: &SharedState,
    cfg: &TunnelConfig,
    logger: Logger,
) -> Result<(CompatSession, u16), TunnelError> {
    let handle = state.handle.clone();
    (logger)(&format!(
        "兼容模式: 在服务器上启动 stdio 转发助手 (请求端口 {})",
        cfg.remote_port
    ));

    let target = format!("{}:{}", cfg.local_proxy_host, cfg.local_proxy_port);
    let helper_cmd = format!("{} {}", HELPER_PY, cfg.remote_port);

    // 通道建立与端口上报在 open_helper 内同步完成 (端口 0 时必须知道实际端口
    // 才算建立成功; 助手秒退/上报异常也能在建连阶段报错, 而非静默空转):
    // 一个会话通道按顺序服务多个本地 SOCKS 连接。
    // 通道两侧使用帧协议: [u32 BE 长度][数据], 长度=0 表示连接结束。
    // 服务器端每个连接 -> 通道里依次: 数据帧... 结束帧; 本机侧对称。
    // 读通道的循环放在独立任务中, 经 mpsc 把帧交给转发循环 (避免借用冲突)。
    let chan = handle
        .lock()
        .await
        .channel_open_session()
        .await
        .map_err(|e| TunnelError::ChannelOpen {
            what: "会话通道".into(),
            reason: e.to_string(),
        })?;
    chan.exec(true, helper_cmd.as_str())
        .await
        .map_err(|e| TunnelError::Protocol(format!("启动转发助手失败: {e}")))?;
    let chan = chan.into_stream();

    use tokio::io::split;

    enum FrameMsg {
        Payload(Vec<u8>),
        End, // 连接结束 (服务器端 EOF)
        ChannelClosed,
    }
    enum LocalMsg {
        Data(Vec<u8>),
        Closed,
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<FrameMsg>(32);

    // 通道拆分为读写两半: 读半部给帧解析任务, 写半部由转发循环独占
    let (mut chan_r, mut chan_w) = split(chan);

    // 标记帧: 触发并吸收本机->服务器方向 (sshd 写 helper stdin) 的首次注入。
    // helper 以"跳过注入"状态开始, 会丢弃标记帧前的注入数据。
    chan_w
        .write_all(&frame::MARKER)
        .await
        .map_err(|e| TunnelError::Protocol(format!("写标记帧失败: {e}")))?;
    (logger)("已发送标记帧 (吸收服务器端写注入)");

    // 端口 0: 读助手上报的端口行 (逐字节读, 不留缓冲残余给帧解析器)
    let bound_port = if cfg.remote_port == 0 {
        let p = read_port_line(&mut chan_r).await?;
        (logger)(&format!("转发助手已启动, 动态分配端口 {p}"));
        p
    } else {
        (logger)(&format!(
            "转发助手已启动 (监听 127.0.0.1:{})",
            cfg.remote_port
        ));
        cfg.remote_port as u16
    };

    let logger2 = logger;
    // helper 通道计数 +1 (至此所有可失败步骤已过), 两个后台任务都结束后
    // 由收尾任务 -1 —— abort 拆除同样覆盖 (JoinHandle 对 abort 返回 Err 也完成)。
    let count = state.open_channels.fetch_add(1, Ordering::Relaxed) + 1;
    shared::warn_exhausted(count, state.budget, &logger2);
    // 帧读取任务: 通道字节流 -> 帧 -> 队列。
    // 帧协议 (标记帧/CRC/分块/注入同步) 在 transport::frame, 独立单测覆盖;
    // 此任务只做 IO: 读通道 -> feed 解析器 -> 转发帧给转发循环,
    // 以及 partial 超时 (帧尾丢失, 注入截断) 的计时与重置。
    let reader_task = {
        let logger3 = logger2.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut parser = FrameParser::new();
            let mut tmp = [0u8; 16384];
            let mut partial_since: Option<tokio::time::Instant> = None;
            let partial_timeout = std::time::Duration::from_secs(5);
            loop {
                // partial 计时: 首次观察到未完成帧时起表, 补齐即重置
                if parser.partial_pending() {
                    let since = *partial_since.get_or_insert_with(tokio::time::Instant::now);
                    if since.elapsed() > partial_timeout {
                        partial_since = None;
                        parser.on_partial_timeout(|m| (logger3)(m));
                        if tx.send(FrameMsg::End).await.is_err() {
                            return;
                        }
                    }
                } else {
                    partial_since = None;
                }
                match chan_r.read(&mut tmp).await {
                    Ok(0) | Err(_) => {
                        let _ = tx.send(FrameMsg::ChannelClosed).await;
                        break;
                    }
                    Ok(n) => {
                        if pt_dump_enabled() {
                            let head: String = tmp[..n]
                                .iter()
                                .take(24)
                                .map(|x| format!("{x:02x}"))
                                .collect();
                            (logger3)(&format!("READ n={n} head={head}"));
                        }
                        for fr in parser.feed_with(&tmp[..n], |m| (logger3)(m)) {
                            let msg = match fr {
                                Frame::Payload(p) => FrameMsg::Payload(p),
                                Frame::End => FrameMsg::End,
                            };
                            if tx.send(msg).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            (logger3)("通道读取任务结束");
        })
    };

    // 转发循环 (后台任务): 每个连接: 首帧到达 -> 连本地代理 -> 双向转发 -> 结束帧 -> 下一连接
    let pt_dump = pt_dump_enabled();
    let pdump = move |logger: &Logger, msg: &str| {
        if pt_dump {
            logger(&msg.to_string());
        }
    };
    let fwd_task = tokio::spawn(async move {
        'outer: loop {
            // 等待连接首帧
            let first = match rx.recv().await {
                Some(FrameMsg::Payload(p)) => p,
                Some(FrameMsg::End) => continue,
                Some(FrameMsg::ChannelClosed) | None => break,
            };
            // 注: 不设首帧判定 — 兼容模式的客户端可能以任意字节开头
            // (SOCKS5 握手为 0x05, 但 echo 类原始数据可任意)。注入转储已由
            // 标记帧同步 (跳过注入模式) 可靠处理, 这里直接转发首帧。
            let mut local = match TcpStream::connect(&target).await {
                Ok(s) => {
                    (logger2)(&format!(
                        "已连接本地代理, 开始转发 (首帧 {} 字节)",
                        first.len()
                    ));
                    s
                }
                Err(e) => {
                    (logger2)(&format!("连接本地代理 {target} 失败: {e}"));
                    break;
                }
            };
            if local.write_all(&first).await.is_err() {
                (logger2)("写首帧到本地代理失败");
                continue;
            }
            // 本地连接拆分: 读半部给读任务, 写半部由本循环独占。
            // 每个连接使用独立的 rx_local channel: 上一连接的读任务在连接
            // 结束后仍会发送 Closed, 复用同一 channel 会让下一连接误收到
            // 残留的关闭信号 (第一个连接成功、后续连接立即"结束"的根因)。
            let (tx_local, mut rx_local) = tokio::sync::mpsc::channel::<LocalMsg>(32);
            let (mut r_local, mut w_local) = local.into_split();
            let tx_local2 = tx_local.clone();
            tokio::spawn(async move {
                let mut tmp = [0u8; 16384];
                loop {
                    match r_local.read(&mut tmp).await {
                        Ok(0) | Err(_) => {
                            let _ = tx_local2.send(LocalMsg::Closed).await;
                            break;
                        }
                        Ok(n) => {
                            if tx_local2
                                .send(LocalMsg::Data(tmp[..n].to_vec()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            });

            let mut closed = false;
            let mut fwd_step = 0usize;
            while !closed {
                fwd_step += 1;
                tokio::select! {
                    m = rx.recv() => match m {
                        Some(FrameMsg::Payload(p)) => {
                            pdump(&logger2, &format!("FWD#{fwd_step} rx Payload {}", p.len()));
                            if w_local.write_all(&p).await.is_err() {
                                closed = true;
                            }
                        }
                        Some(FrameMsg::End) => {
                            (logger2)("收到 End 帧 (服务器连接结束)");
                            closed = true;
                        }
                        Some(FrameMsg::ChannelClosed) | None => break 'outer,
                    },
                    m = rx_local.recv() => match m {
                        Some(LocalMsg::Data(d)) => {
                            pdump(&logger2, &format!("FWD#{fwd_step} local Data {}", d.len()));
                            // 每个写单元 = [标记帧][帧] (frame::encode_payload):
                            // 注入转储前置在每次写的数据前, helper 的解析器
                            // 丢弃标记帧前的一切, 帧校验 CRC。
                            // 注: 本机->服务器方向实测无注入 (sshd 写管道不被
                            // 审计), 此处无需分块; 大帧由 helper 的 feed 状态机
                            // 与 5s partial 超时兜底。
                            if chan_w.write_all(&frame::encode_payload(&d)).await.is_err() {
                                break 'outer;
                            }
                            (logger2)(&format!("回写帧 {} 字节", d.len()));
                        }
                        Some(LocalMsg::Closed) | None => {
                            // 本地连接结束 -> 发送结束帧 (frame::encode_end,
                            // 非零编码, 与 libonion 空审计记录区分)
                            (logger2)("本地代理连接结束, 发送结束帧");
                            if chan_w.write_all(&frame::encode_end()).await.is_err() {
                                break 'outer;
                            }
                            closed = true;
                        }
                    },
                }
            }
            (logger2)("连接转发结束");
        }
        (logger2)("隧道会话通道已结束");
    });

    // helper 通道计数收尾: 两个后台任务都结束 (自然关闭或 abort) 后递减
    let reader_abort = reader_task.abort_handle();
    let fwd_abort = fwd_task.abort_handle();
    let counter = state.open_channels.clone();
    tokio::spawn(async move {
        let _ = fwd_task.await;
        let _ = reader_task.await;
        counter.fetch_sub(1, Ordering::Relaxed);
    });

    Ok((
        CompatSession {
            reader: reader_abort,
            forwarder: fwd_abort,
        },
        bound_port,
    ))
}

/// PT_DUMP 环境变量: 转发循环/读取任务的逐帧调试转储开关
fn pt_dump_enabled() -> bool {
    std::env::var("PT_DUMP").is_ok()
}

/// 读助手上报的端口行 `PORT <n>\n` (仅 remote_port=0 时调用)。
/// 逐字节读: 不留缓冲残余, 之后帧解析器从干净状态开始。
/// 该行是 helper 的**首条 stdout 写入**——注入转储是"前次写入的副本",
/// 首写无前史, 必然干净抵达; 若 helper 秒退/上报异常, 在此报错而非静默空转。
async fn read_port_line<R: tokio::io::AsyncRead + Unpin>(
    chan_r: &mut R,
) -> Result<u16, TunnelError> {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = tokio::time::timeout_at(deadline, chan_r.read(&mut b))
            .await
            .map_err(|_| TunnelError::Protocol("等待助手上报端口超时".into()))?
            .map_err(|e| TunnelError::Protocol(format!("读助手端口行失败: {e}")))?;
        if n == 0 {
            return Err(TunnelError::Protocol(
                "转发助手提前退出 (未上报端口)——服务器可能没有 python3".into(),
            ));
        }
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
        if line.len() > 32 {
            return Err(TunnelError::Protocol("助手端口行超长".into()));
        }
    }
    let s = String::from_utf8_lossy(&line);
    s.trim()
        .strip_prefix("PORT ")
        .and_then(|r| r.trim().parse::<u16>().ok())
        .filter(|&p| p != 0)
        .ok_or_else(|| TunnelError::Protocol(format!("助手端口行异常: {}", s.trim())))
}

/// python3 stdio 桥接助手: 监听 127.0.0.1:<port>, 每个连接接到 SSH 会话通道 stdin/stdout。
/// 串行服务 (一个连接结束后接受下一个)。注意: 脚本内禁止使用单引号 (经 bash -c 传递)。
///
/// 帧协议: 通道两侧双向传输 [u32 BE 长度][u32 BE CRC32][数据]; 结束帧 =
/// [00000004][crc32(DEADBEEF)][DE AD BE EF] (非零编码, 与 libonion 空审计记录
/// [00000000] 区分 —— 后者字节与零长度结束帧完全相同, 无法区分)。
/// 每个写单元 = [标记帧][帧] (见下方注入防护)。会话通道是复用的 (多个 TCP 连接
/// 共享一条通道), 帧让本机端能区分连接边界; 连接内数据可拆成多个帧 (helper 的
/// stdout 写入按 4KB 分块, 见截断防护)。
///
/// 注入防护 (标记帧协议): 云主机安全组件 (libonion) 注入 sshd 的通道 socket 写
/// 路径, 每次写入前前置审计转储 (前次写入的流量副本, 逐连接概率出现):
/// - helper -> 本机 (sshd 写通道 socket): 每次 helper stdout 写入都被前置转储;
/// - 本机 -> helper (sshd 写 helper stdin 管道): 实测无注入 (管道写不被审计)。
/// 双方都以"跳过注入"状态开始, 丢弃一切字节直到收到对方发来的标记帧; 标记帧
/// 本身也丢弃 (幂等同步点, 任何状态都吸收)。之后按帧协议解析, 帧前若仍有转储
/// 则被"丢弃标记帧前的一切"逻辑吸收。标记帧: [00 00 00 08][DE AD BE EF DE AD BE EF]。
///
/// 截断防护: libonion 注入大写入时 sshd 的通道写被截断 (~16KB 内部缓冲), 帧尾
/// 丢失。故 helper 的 stdout 写入按 4KB 分块: 转储 (≤4KB) + 新帧恒 < 16KB, 从根源
/// 避免截断。CRC32 校验 (与 python zlib.crc32 一致) 检测残余损坏帧, 损坏时发 End
/// 丢弃该连接 (上层 SOCKS 客户端自动重试); partial 5s 不补齐则超时重置。
/// 注意: 脚本内禁止使用单引号 (经 bash -c 传递)。
/// 帧协议常量 (MARKER/END_PAYLOAD)、编解码 (encode_payload/encode_end) 与解析
/// 状态机 (FrameParser) 在 `transport::frame` (独立单测覆盖); 本常量是服务器侧
/// python3 对称实现。
///
/// helper 启动后: 预热自连 -> (端口 0 时) 上报 `PORT <n>` 行 -> 写标记帧。**每个连接的数据前都写标记帧**: 注入
/// 转储可能分批到达且包含流量副本, 与真实帧无法区分, 本机端以"跳过注入"模式
/// 丢弃标记帧之前的一切字节。读 stdin 时同样先跳过注入直到本机发来的标记帧。
/// 无活动连接 (c is None) 时丢弃数据帧, 不崩溃。
const HELPER_PY: &str = "python3 -c 'import socket,select,os,sys,zlib,time
p=int(sys.argv[1])
p0=(p==0)
def dbg(m):
 try:
  f=open(\"/tmp/hc_dbg.log\",\"a\")
  f.write(m+\"\\n\")
  f.close()
 except Exception:
  pass
M=b\"\\x00\\x00\\x00\\x08\\xde\\xad\\xbe\\xef\\xde\\xad\\xbe\\xef\"
END=b\"\\xde\\xad\\xbe\\xef\"
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((\"127.0.0.1\",p))
p=s.getsockname()[1]
s.listen(8)
try:
 w=socket.socket(); w.settimeout(3)
 w.connect((\"127.0.0.1\",p))
 c2,a=s.accept(); c2.settimeout(3)
 w.send(b\"X\"); c2.recv(1)
 c2.close(); w.close()
except Exception:
 pass
if p0:
 sys.stdout.buffer.write(b\"PORT %d\\n\"%p)
 sys.stdout.buffer.flush()
sys.stdout.buffer.write(M)
sys.stdout.buffer.flush()
buf=b\"\"
c=None
partial=None
partial_since=None
cid=0
def feed(d):
 global buf,c,partial,partial_since
 buf+=d
 while True:
  if partial is not None:
   if len(buf)<8+partial: return
   if partial==8 and buf[4:12]==M[4:]:
    buf=buf[12:]
    partial=None
    continue
   if partial==4 and buf[8:12]==END:
    buf=buf[12:]
    partial=None
    dbg(\"feed_end\")
    if c is not None:
     try: c.close()
     except Exception: pass
    c=None
    continue
   try:
    ok=zlib.crc32(buf[8:8+partial])==int.from_bytes(buf[4:8],\"big\")
   except Exception:
    ok=False
   if not ok:
    dbg(\"feed_badcrc_partial\")
    if c is not None:
     try: c.close()
     except Exception: pass
    c=None
    buf=buf[8+partial:]
    partial=None
    continue
   if c is not None:
    try:
     c.sendall(buf[8:8+partial])
     dbg(\"feed_ok id=\"+str(cid)+\" n=\"+str(partial))
    except Exception as e:
     dbg(\"feed_exc id=\"+str(cid)+\" n=\"+str(partial)+\" \"+repr(e))
   else:
    dbg(\"feed_drop id=\"+str(cid)+\" n=\"+str(partial))
   buf=buf[8+partial:]
   partial=None
  i=buf.find(M)
  if i<0:
   if len(buf)>len(M)-1:
    buf=buf[len(M)-1:]
   return
  buf=buf[i+len(M):]
  if len(buf)<8: return
  n=int.from_bytes(buf[:4],\"big\")
  if n==8 and buf[4:12]==M[4:]:
   buf=buf[12:]
   continue
  if n==4 and buf[8:12]==END:
   buf=buf[12:]
   dbg(\"feed_end\")
   if c is not None:
    c.close()
   c=None
   continue
  if n==0:
   buf=buf[4:]
   continue
  if len(buf)<8+n:
   partial=n
   partial_since=time.time()
   dbg(\"feed_partial \"+str(n))
   return
  try:
   ok=zlib.crc32(buf[8:8+n])==int.from_bytes(buf[4:8],\"big\")
  except Exception:
   ok=False
  if not ok:
   dbg(\"feed_badcrc \"+str(n))
   if c is not None:
    try: c.close()
    except Exception: pass
   c=None
   buf=buf[8+n:]
   continue
  if c is not None:
   try:
    c.sendall(buf[8:8+n])
    dbg(\"feed_ok id=\"+str(cid)+\" n=\"+str(n))
   except Exception as e:
    dbg(\"feed_exc id=\"+str(cid)+\" n=\"+str(n)+\" \"+repr(e))
  else:
   dbg(\"feed_drop id=\"+str(cid)+\" n=\"+str(n))
  buf=buf[8+n:]
while True:
 r,_,_=select.select([s,sys.stdin],[],[],0.5)
 if sys.stdin in r:
  d=os.read(0,65536)
  if not d: sys.exit(0)
  feed(d)
  continue
 if s in r:
  c,a=s.accept()
  cid+=1
  dbg(\"accept id=\"+str(cid))
  sys.stdout.buffer.write(M)
  sys.stdout.buffer.flush()
  try:
   while True:
    if partial is not None and partial_since is not None and time.time()-partial_since>5:
     dbg(\"feed_partial_timeout\")
     partial=None
     partial_since=None
     buf=b\"\"
     if c is not None:
      try: c.close()
      except Exception: pass
     c=None
     break
    r,_,_=select.select([c,sys.stdin],[],[],0.3)
    if sys.stdin in r:
     d=os.read(0,65536)
     if not d: dbg(\"stdin EOF\"); sys.exit(0)
     feed(d)
     if c is None: break
    if c in r:
     d=c.recv(65536)
     if not d:
      dbg(\"ceof id=\"+str(cid))
      sys.stdout.buffer.write(M+len(END).to_bytes(4,\"big\")+zlib.crc32(END).to_bytes(4,\"big\")+END)
      sys.stdout.buffer.flush()
      break
     for i in range(0,len(d),4096):
      ch=d[i:i+4096]
      sys.stdout.buffer.write(M+len(ch).to_bytes(4,\"big\")+zlib.crc32(ch).to_bytes(4,\"big\")+ch)
      sys.stdout.buffer.flush()
  except Exception as e:
   dbg(\"loop EXC \"+repr(e))
  if c is not None:
   c.close()'";
