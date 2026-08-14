//! 反向 SSH 隧道核心
//!
//! 拓扑: 远程服务器监听 <remote_port> --SSH--> 本机 --TCP--> 本地SOCKS代理(如 v2cloud 127.0.0.1:7892)
//!
//! 等价于 `ssh -R <remote_port>:127.0.0.1:<local_socks_port> user@server`
//! 由 russh (纯 Rust) 实现, 无需外部 ssh/sshpass, 密码由 GUI 传入、仅存内存。
//!
//! # 两种工作模式 (自动选择)
//!
//! 1. **标准模式 (tcpip_forward)**: 请求服务器监听 remote_port, 转发通道由 sshd 建立。
//!    开销最小, 等价原生 `ssh -R`。
//!
//! 2. **兼容模式 (session 通道)**: 通过 exec 在服务器上启动一个 python3 stdio 桥接助手,
//!    助手监听 127.0.0.1:remote_port 并把每个连接接到 SSH 会话通道的 stdin/stdout,
//!    本机把会话通道桥接到本地 SOCKS。语义等价, 但数据走会话通道。
//!
//! 为什么需要兼容模式: 部分云主机安全组件 (如腾讯云主机安全 libonion) 通过
//! /etc/ld.so.preload 注入 sshd, 会在 forwarded-tcpip 通道建立时写入会话审计数据
//! 并破坏数据流。会话通道不受影响。工具连接时自动探测:
//! 建立转发通道后让服务器连一次转发端口, 检查通道首字节 (本地端一定是 SOCKS5,
//! 首字节应为 0x05; 被注入时首字节是审计数据的 0x00), 发现污染即切换兼容模式。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use russh::client::{self, ChannelOpenHandle, Msg, Session};
use russh::Channel;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::AppState;

/// 隧道连接配置
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub server_host: String,
    pub server_port: u16,
    pub username: String,
    /// 密码仅用于内存中的认证, 不落盘
    pub password: String,
    /// 服务器上监听的端口 (相当于 ssh -R 的远端端口)
    pub remote_port: u32,
    /// 本机 SOCKS 代理地址
    pub local_proxy_host: String,
    pub local_proxy_port: u16,
}

/// 日志回调 (定义在 ssh.rs, 三种隧道模式共用)
pub use crate::ssh::Logger;

/// russh 客户端 Handler: 接收服务器转发的反向连接并桥接到本地 SOCKS
pub struct TunnelHandler {
    cfg: TunnelConfig,
    logger: Logger,
    /// 首字节检查发现通道被注入审计数据时置位 (云主机安全组件场景)
    corrupted: Arc<AtomicBool>,
}

impl client::Handler for TunnelHandler {
    type Error = russh::Error;

    /// 信任任意服务器公钥 (MVP; 后续可升级为 known_hosts 校验)
    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    /// 服务器有流量要转发回来时被调用:
    /// 1. 检查通道首字节是否被服务器端组件注入审计数据
    /// 2. 确认通道 (reply.accept)
    /// 3. 连本地 SOCKS 代理, 双向桥接 SSH channel <-> SOCKS socket
    ///
    /// 注意: 桥接必须放进独立任务。russh 的连接消息循环会 await 本 handler
    /// 返回的 future, 若在这里 copy_bidirectional 直到结束, 通道数据永远不会被投递。
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let target = format!(
            "{}:{}",
            self.cfg.local_proxy_host, self.cfg.local_proxy_port
        );
        let logger = self.logger.clone();
        let corrupted = self.corrupted.clone();
        // 与 russh 自身测试相同: 先在任务里 into_stream, handler 再 accept
        tokio::spawn(async move {
            let mut chan = channel.into_stream();

            // 首字节检查: 本地端一定是 SOCKS5, 每个代理连接的首字节应为 0x05。
            // 云主机安全组件 (如腾讯云 libonion) 在转发通道建立时注入审计数据,
            // 首字节是其长度前缀的 0x00 — 据此识别并标记污染, 由上层切换兼容模式。
            // 其他首字节 (如探测命令写入的 0x58 'X') 是探测数据, 静默丢弃, 不算污染。
            let mut head = [0u8; 1];
            let verdict =
                match tokio::time::timeout(std::time::Duration::from_secs(2), chan.read(&mut head))
                    .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                        // 无数据: 探测连接或对端已断开, 静默关闭
                        (logger)("转发通道无数据, 关闭");
                        None
                    }
                    Ok(Ok(_)) if head[0] == 0x05 => Some(true), // SOCKS5 握手, 正常
                    Ok(Ok(_)) if head[0] == 0x00 => {
                        // 首字节 0x00: 服务器端注入的审计数据 (长度前缀特征)
                        (logger)(
                            "检测到转发通道首字节 0x00, 疑似服务器端注入审计数据 (云主机安全组件)",
                        );
                        corrupted.store(true, Ordering::Relaxed);
                        None
                    }
                    Ok(Ok(_)) => {
                        // 其他首字节: 探测数据 (如 0x58 'X'), 静默丢弃
                        (logger)(&format!(
                            "转发通道首字节 0x{:02x} 非 SOCKS5 (探测数据?), 关闭",
                            head[0]
                        ));
                        None
                    }
                };
            if verdict.is_none() {
                return;
            }

            // 桥接: 先连本地 SOCKS, 首字节写回流, 再双向复制
            let mut stream = match TcpStream::connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    (logger)(&format!("连接本地代理 {target} 失败: {e}"));
                    return;
                }
            };
            (logger)(&format!("已连接本地代理 {target}"));
            if let Err(e) = stream.write_all(&head).await {
                (logger)(&format!("写回首字节失败: {e}"));
                return;
            }

            let r = copy_bidirectional(&mut stream, &mut chan).await;
            (logger)(&format!("连接关闭 ({r:?})"));
        });
        reply.accept().await;
        Ok(())
    }
}

/// 连接 + 密码认证 (两种模式共用), 返回会话与污染标记。
/// 认证逻辑共用 ssh::connect_auth。
async fn connect_and_auth(
    cfg: &TunnelConfig,
    logger: &Logger,
) -> Result<(client::Handle<TunnelHandler>, Arc<AtomicBool>), String> {
    let corrupted = Arc::new(AtomicBool::new(false));
    let handler = TunnelHandler {
        cfg: cfg.clone(),
        logger: logger.clone(),
        corrupted: corrupted.clone(),
    };
    let session = crate::ssh::connect_auth(
        &cfg.server_host,
        cfg.server_port,
        &cfg.username,
        &cfg.password,
        handler,
        logger,
    )
    .await?;
    Ok((session, corrupted))
}

/// 标准模式: 请求服务器监听 remote_port (等价 ssh -R), 并探测通道是否被注入污染。
/// 探测失败 (端口不可连 / 地址族不对) 或检测到注入时返回 Err, 由 run_tunnel 切换兼容模式。
async fn try_tcpip_forward(
    cfg: &TunnelConfig,
    logger: &Logger,
) -> Result<(client::Handle<TunnelHandler>, Arc<AtomicBool>), String> {
    let (session, corrupted) = connect_and_auth(cfg, logger).await?;
    // bind_address 必须用 "localhost": OpenSSH 的 GatewayPorts 检查只放行
    // "localhost" 字面值 ("127.0.0.1"/"0.0.0.0" 会被拒绝或行为不稳定)。
    // 若 sshd 把 localhost 解析成 IPv6, 探测会失败并自动切换兼容模式。
    let actual_port = session
        .tcpip_forward("localhost", cfg.remote_port)
        .await
        .map_err(|e| format!("请求反向端口转发失败: {e}"))?;
    (logger)(&format!(
        "服务器已监听 127.0.0.1:{actual_port} (转发到 127.0.0.1:{})",
        cfg.local_proxy_port
    ));

    // 探测: 让服务器连一次转发端口并写入 1 字节, 主动触发转发通道与可能的注入:
    // - PROBE_FAIL (连不上): 转发不可用 (地址族/端口被占) -> 切换兼容模式
    // - PROBE_OK 且 corrupted (首字节 0x00 = 注入特征): 通道被审计数据污染 -> 切换兼容模式
    // - PROBE_OK 且未 corrupted (首字节 0x58 = 探测的 X, 干净): 标准模式可用
    // 写数据探测比被动等待可靠: 注入发生在"进程首次写"时, 探测写入必然触发。
    let probe = session
        .channel_open_session()
        .await
        .map_err(|e| format!("打开探测通道失败: {e}"))?;
    probe
        .exec(
            true,
            format!(
                "exec 3<>/dev/tcp/127.0.0.1/{0} && echo PROBE_OK && echo X >&3 || echo PROBE_FAIL",
                cfg.remote_port
            ),
        )
        .await
        .map_err(|e| format!("执行探测命令失败: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let mut probe_out = Vec::new();
    let mut stream = probe.into_stream();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut probe_out),
    )
    .await;
    let out = String::from_utf8_lossy(&probe_out);
    (logger)(&format!("端口探测结果: {}", out.trim()));
    if !out.contains("PROBE_OK") {
        return Err(format!("转发端口探测失败, 服务器输出: {}", out.trim()));
    }
    Ok((session, corrupted))
}

/// 兼容模式: 服务器端 python3 stdio 桥接助手 + 会话通道, 语义等价 ssh -R。
/// 服务器需有 python3 (主流发行版默认自带; 亦可用 socat/nc 替代, 当前实现用 python3)。
pub async fn run_tunnel_session(
    cfg: TunnelConfig,
    logger: Logger,
) -> Result<Arc<tokio::sync::Mutex<client::Handle<TunnelHandler>>>, String> {
    let (session, _) = connect_and_auth(&cfg, &logger).await?;
    (logger)(&format!(
        "兼容模式: 在服务器上启动 stdio 转发助手 (监听 127.0.0.1:{})",
        cfg.remote_port
    ));

    let handle = Arc::new(tokio::sync::Mutex::new(session));
    let target = format!("{}:{}", cfg.local_proxy_host, cfg.local_proxy_port);
    let helper_cmd = format!("{} {}", HELPER_PY, cfg.remote_port);

    let h = handle.clone();
    let logger2 = logger.clone();
    // 桥接任务: 一个会话通道按顺序服务多个本地 SOCKS 连接。
    // 通道两侧使用帧协议: [u32 BE 长度][数据], 长度=0 表示连接结束。
    // 服务器端每个连接 -> 通道里依次: 数据帧... 结束帧; 本机侧对称。
    // 读通道的循环放在独立任务中, 经 mpsc 把帧交给转发循环 (避免借用冲突)。
    tokio::spawn(async move {
        let chan = match h.lock().await.channel_open_session().await {
            Ok(c) => c,
            Err(e) => {
                (logger2)(&format!("打开会话通道失败: {e}"));
                return;
            }
        };
        if let Err(e) = chan.exec(true, helper_cmd.as_str()).await {
            (logger2)(&format!("启动转发助手失败: {e}"));
            return;
        }
        (logger2)("转发助手已启动");
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
        if chan_w.write_all(&MARKER).await.is_err() {
            (logger2)("写标记帧失败");
            return;
        }
        (logger2)("已发送标记帧 (吸收服务器端写注入)");

        // 帧读取任务: 通道字节流 -> 帧 -> 队列
        // 服务器端组件 (libonion) 注入 sshd 的每次写通道, 注入转储 (帧格式,
        // 含流量副本, 无法与真实帧区分) 前置在每次写的数据前。双方 (helper
        // 与本机) 每个写单元 = [标记帧][帧], 解析器用部分帧状态机:
        // - 有未完成帧 (partial): 直接补齐 — 帧尾残余是真实数据, 不可能是注入;
        // - 无未完成帧: 扫描标记帧, 丢弃其前的一切 — 此刻只可能是注入转储。
        // 标记帧 (长度 8 的帧, 数据 DEADBEEF×2) 在任何状态下无条件丢弃。
        // 帧 = [u32 BE 长度][u32 BE CRC32][数据]; 结束帧 = [00000004][crc][DEADBEEF]
        // (非零编码, 与 libonion 空审计记录 [00000000] 区分)。
        // 实测: libonion 注入大写入时 sshd 的通道写被截断 (~16KB 内部缓冲),
        // 注入转储(前次写入的流量副本) + 帧超过 16KB 时帧尾随机丢失。
        // 防护: (1) helper 的 stdout 写入按 4KB 分块 (见 HELPER_PY), 转储+帧
        // 恒 < 16KB, 从根源避免截断; (2) CRC 校验检测残留的损坏帧, 损坏时
        // 丢弃该连接 (发 End, 上层 SOCKS 客户端自动重试) 并重置同步;
        // (3) partial 长期不补齐 (尾部丢失) 时超时重置, 防止解析器卡死。
        let logger3 = logger2.clone();
        let pt_dump = std::env::var("PT_DUMP").is_ok();
        let pdump = move |logger: &Logger, msg: &str| {
            if pt_dump {
                logger(&msg.to_string());
            }
        };
        tokio::spawn(async move {
            let mut buf: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 16384];
            let mut partial: Option<usize> = None;
            let mut partial_since: Option<tokio::time::Instant> = None;
            let partial_timeout = std::time::Duration::from_secs(5);
            // 同步状态: false = 未同步, 扫描标记帧并丢弃其前的一切 (注入);
            // true = 刚消费标记帧, 头部必然是帧 (结束帧/连续标记帧/数据帧)。
            // 注入会复制前次写入的标记帧 (产生 [M][M][f1][M][f2] 布局),
            // 若同步后仍按"扫描标记"处理, 会把标记之间的真实数据帧当注入丢弃。
            let mut synced = false;
            loop {
                if let (Some(plen), Some(since)) = (partial, partial_since) {
                    if since.elapsed() > partial_timeout {
                        // 帧尾丢失 (注入截断): 无法恢复该帧, 关闭当前连接,
                        // 上层重试; 丢弃缓冲重新同步
                        (logger3)(&format!(
                            "帧 {plen} 字节不完整超时 (注入截断), 丢弃连接并重置同步"
                        ));
                        partial = None;
                        partial_since = None;
                        buf.clear();
                        if tx.send(FrameMsg::End).await.is_err() {
                            return;
                        }
                    }
                }
                match chan_r.read(&mut tmp).await {
                    Ok(0) | Err(_) => {
                        let _ = tx.send(FrameMsg::ChannelClosed).await;
                        break;
                    }
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if pt_dump {
                            let hex = |b: &[u8]| -> String {
                                b.iter().map(|x| format!("{x:02x}")).collect::<String>()
                            };
                            let head: String =
                                buf.iter().take(24).map(|x| format!("{x:02x}")).collect();
                            let tail: String = buf
                                .iter()
                                .skip(buf.len().saturating_sub(16))
                                .map(|x| format!("{x:02x}"))
                                .collect();
                            let _ = hex;
                            (logger3)(&format!(
                                "READ n={n} buf={} head={head} tail={tail}",
                                buf.len()
                            ));
                        }
                        loop {
                            // 部分帧: 直接补齐 (帧尾残余是真实数据)
                            if let Some(plen) = partial {
                                pdump(&logger3, &format!("PARTIAL plen={plen} buf={}", buf.len()));
                                if buf.len() < 8 + plen {
                                    break;
                                }
                                if plen == 8 && buf[4..12] == MARKER[4..] {
                                    // 标记帧残片补齐后判定为同步点, 丢弃
                                    buf.drain(..12);
                                    partial = None;
                                    partial_since = None;
                                    continue;
                                }
                                if plen == 4 && buf[8..12] == END_PAYLOAD {
                                    // 结束帧残片补齐 (拆批到达的 [00000004][crc][DEADBEEF])
                                    buf.drain(..12);
                                    partial = None;
                                    partial_since = None;
                                    synced = false;
                                    if tx.send(FrameMsg::End).await.is_err() {
                                        return;
                                    }
                                    continue;
                                }
                                if !frame_crc_ok(&buf, plen) {
                                    // 注入截断导致数据损坏: 丢连接 + 重置同步
                                    (logger3)("CRC 校验失败 (注入截断), 丢弃连接并重置同步");
                                    partial = None;
                                    partial_since = None;
                                    buf.clear();
                                    synced = false;
                                    if tx.send(FrameMsg::End).await.is_err() {
                                        return;
                                    }
                                    break;
                                }
                                let payload = buf[8..8 + plen].to_vec();
                                buf.drain(..8 + plen);
                                partial = None;
                                partial_since = None;
                                synced = false;
                                if tx.send(FrameMsg::Payload(payload)).await.is_err() {
                                    return;
                                }
                                continue;
                            }
                            // 结束帧 = [00 00 00 04][crc32][DE AD BE EF] (12 字节)。
                            // 必须先于标记帧扫描处理: 若滞后, 下一次扫描找到后续标记帧
                            // 后 drain 其前的一切, 会把滞留在缓冲中的结束帧误当注入
                            // 丢弃, 当前连接收不到 End, 后续连接的帧全部串入前一连接。
                            // 注意: 结束帧不得用 [00000000] 编码 —— libonion 的空审计
                            // 记录就是 [00000000], 二者字节完全相同且相邻标记帧布局
                            // 一致 (空记录后随帧标记, 结束帧后随下一连接的接受标记),
                            // 无法区分; 空记录被扫描吸收 (丢弃标记帧前的一切)。
                            if buf.len() >= 12
                                && u32::from_be_bytes(buf[..4].try_into().unwrap()) == 4
                                && buf[8..12] == END_PAYLOAD
                            {
                                buf.drain(..12);
                                if tx.send(FrameMsg::End).await.is_err() {
                                    return;
                                }
                                pdump(&logger3, "EMIT End (完整 12 字节)");
                                continue;
                            }
                            if synced {
                                // 已同步 (刚消费过标记帧): 头部必须是帧 —
                                // 结束帧 / 另一个标记帧 / 数据帧。绝不在此扫描
                                // 标记帧: 标记帧之间是真实数据, 扫描会把它当注入
                                // 丢弃 (旧 bug: [M][M][f1][M][f2] 中 f1 丢失)。
                                if buf.len() < 8 {
                                    break;
                                }
                                let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
                                if len == 0 {
                                    // 空审计记录残留: 丢弃 (结束帧不再是零长度编码)
                                    buf.drain(..4);
                                    pdump(&logger3, "DROP 空记录 len=0");
                                    continue;
                                }
                                if len == 8 && buf.len() >= 12 && buf[4..12] == MARKER[4..] {
                                    // 连续标记帧 (注入副本 + 真实标记): 丢弃, 保持同步
                                    buf.drain(..12);
                                    pdump(&logger3, "DROP 连续标记帧 (保持同步)");
                                    continue;
                                }
                                if buf.len() < 8 + len {
                                    partial = Some(len);
                                    partial_since = Some(tokio::time::Instant::now());
                                    pdump(&logger3, &format!("PARTIAL set len={len}"));
                                    break;
                                }
                                if !frame_crc_ok(&buf, len) {
                                    // 注入截断导致数据损坏: 丢连接 + 重置同步
                                    (logger3)(&format!(
                                        "CRC 校验失败 (注入截断, 帧 {len} 字节), 丢弃连接并重置同步"
                                    ));
                                    buf.drain(..8 + len);
                                    if tx.send(FrameMsg::End).await.is_err() {
                                        return;
                                    }
                                    synced = false;
                                    continue;
                                }
                                let payload = buf[8..8 + len].to_vec();
                                buf.drain(..8 + len);
                                if tx.send(FrameMsg::Payload(payload)).await.is_err() {
                                    return;
                                }
                                pdump(&logger3, &format!("EMIT Payload {len}"));
                                synced = false;
                                continue;
                            }
                            // 未同步: 扫描标记帧, 丢弃其前的一切 (注入)
                            match find_marker(&buf) {
                                None => {
                                    // 只保留可能跨批的标记帧尾部
                                    let keep = MARKER.len() - 1;
                                    if buf.len() > keep {
                                        buf.drain(..buf.len() - keep);
                                    }
                                    pdump(&logger3, &format!("SCAN none keep (buf={})", buf.len()));
                                    break;
                                }
                                Some(pos) => {
                                    pdump(&logger3, &format!("SCAN pos={pos} (buf={})", buf.len()));
                                    buf.drain(..pos + MARKER.len());
                                    synced = true;
                                    // 回到循环顶部: 标记帧后可能是结束帧
                                    // (顶部检查), 也可能是数据帧 (synced 分支)
                                }
                            }
                        }
                    }
                }
            }
            (logger3)("通道读取任务结束");
        });

        // 转发循环: 每个连接: 首帧到达 -> 连本地代理 -> 双向转发 -> 结束帧 -> 下一连接
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
                            // 每个写单元 = [标记帧][帧]: 注入转储前置在每次
                            // 写的数据前, helper 的解析器丢弃标记帧前的一切。
                            // 帧 = [长度][CRC32][数据], helper 端校验 CRC。
                            // 注: 本机->服务器方向实测无注入 (sshd 写管道不被
                            // 审计), 此处无需分块; 大帧由 helper 的 feed 状态机
                            // 与 5s partial 超时兜底。
                            let mut f = Vec::with_capacity(MARKER.len() + 8 + d.len());
                            f.extend_from_slice(&MARKER);
                            f.extend_from_slice(&(d.len() as u32).to_be_bytes());
                            f.extend_from_slice(&crc32(&d).to_be_bytes());
                            f.extend_from_slice(&d);
                            if chan_w.write_all(&f).await.is_err() {
                                break 'outer;
                            }
                            (logger2)(&format!("回写帧 {} 字节", d.len()));
                        }
                        Some(LocalMsg::Closed) | None => {
                            // 本地连接结束 -> 发送结束帧 ([00000004][crc][DEADBEEF],
                            // 非零编码, 与 libonion 空审计记录区分)
                            (logger2)("本地代理连接结束, 发送结束帧");
                            let mut f = Vec::with_capacity(MARKER.len() + 12);
                            f.extend_from_slice(&MARKER);
                            f.extend_from_slice(&4u32.to_be_bytes());
                            f.extend_from_slice(&crc32(&END_PAYLOAD).to_be_bytes());
                            f.extend_from_slice(&END_PAYLOAD);
                            if chan_w.write_all(&f).await.is_err() {
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

    Ok(handle)
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
const MARKER: [u8; 12] = [
    0x00, 0x00, 0x00, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
];

/// 结束帧载荷 (非零, 与 libonion 空审计记录 [00000000] 区分)。
/// 结束帧 = [00 00 00 04][crc32(END_PAYLOAD)][END_PAYLOAD] (12 字节, 前带标记帧)。
const END_PAYLOAD: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// 在 buf 中查找标记帧位置 (用于跳过注入模式)
fn find_marker(buf: &[u8]) -> Option<usize> {
    buf.windows(MARKER.len()).position(|w| w == MARKER)
}

/// 标准 CRC32 (与 python zlib.crc32 一致), 帧校验用。
/// 帧格式: [u32 BE 长度][u32 BE CRC32][数据]。
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// 校验 buf 头部是否构成完整合法帧: [长度][CRC32][数据] 且 CRC 匹配
fn frame_crc_ok(buf: &[u8], len: usize) -> bool {
    if buf.len() < 8 + len {
        return false;
    }
    let crc = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    crc32(&buf[8..8 + len]) == crc
}

/// helper 启动后: 预热自连 -> 写标记帧。**每个连接的数据前都写标记帧**: 注入
/// 转储可能分批到达且包含流量副本, 与真实帧无法区分, 本机端以"跳过注入"模式
/// 丢弃标记帧之前的一切字节。读 stdin 时同样先跳过注入直到本机发来的标记帧。
/// 无活动连接 (c is None) 时丢弃数据帧, 不崩溃。
const HELPER_PY: &str = "python3 -c 'import socket,select,os,sys,zlib,time
p=int(sys.argv[1])
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
s.listen(8)
try:
 w=socket.socket(); w.settimeout(3)
 w.connect((\"127.0.0.1\",p))
 c2,a=s.accept(); c2.settimeout(3)
 w.send(b\"X\"); c2.recv(1)
 c2.close(); w.close()
except Exception:
 pass
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

/// 隧道会话句柄与污染标记 (标记在运行期被 handler 置位, 由 start_tunnel 监控)
pub type TunnelSession = (
    Arc<tokio::sync::Mutex<client::Handle<TunnelHandler>>>,
    Arc<AtomicBool>,
);

/// 建立隧道会话并返回句柄。调用方负责保持句柄存活 (drop 即断开)。
/// 自动选择模式: 标准转发通道被服务器端组件污染时切换到兼容模式。
pub async fn run_tunnel(cfg: TunnelConfig, logger: Logger) -> Result<TunnelSession, String> {
    match try_tcpip_forward(&cfg, &logger).await {
        Ok((session, corrupted)) => {
            if corrupted.load(Ordering::Relaxed) {
                (logger)(
                    "检测到服务器转发通道被注入审计数据 (常见于云主机安全组件), 切换兼容模式...",
                );
                return Ok((
                    run_tunnel_session(cfg, logger).await?,
                    Arc::new(AtomicBool::new(false)),
                ));
            }
            Ok((Arc::new(tokio::sync::Mutex::new(session)), corrupted))
        }
        Err(e) => {
            (logger)(&format!("标准转发模式不可用 ({e}), 改用兼容模式"));
            Ok((
                run_tunnel_session(cfg, logger).await?,
                Arc::new(AtomicBool::new(false)),
            ))
        }
    }
}

/// GUI 入口: 建立隧道并常驻后台直到断开。
/// 标准模式下若运行期检测到转发通道被注入 (探测漏检的兜底), 自动重建为兼容模式。
/// 日志与状态通过调用方提供的闭包转发到 GUI (与具体事件格式解耦)。
pub async fn start_tunnel(
    app: tauri::AppHandle,
    cfg: TunnelConfig,
    logger: Logger,
    on_status: Arc<dyn Fn(&str) + Send + Sync>,
) -> Result<(), String> {
    use tauri::Manager;
    let state = app.state::<AppState>();

    let (mut session, corrupted) = run_tunnel(cfg.clone(), logger.clone()).await?;
    let mut rebuilt = corrupted.load(Ordering::Relaxed); // 已在 run_tunnel 内切过兼容模式

    // 存入全局状态以便断开
    {
        let mut guard = state.remote_session.lock().await;
        *guard = Some((session.clone(), corrupted.clone()));
    }
    (on_status)("connected");

    // 保持会话: 直到 is_closed (连接断开或手动 drop), 或运行期检测到注入后重建
    loop {
        let (closed, polluted) = {
            let guard = state.remote_session.lock().await;
            let closed = match guard.as_ref() {
                Some((arc, _)) => arc.lock().await.is_closed(),
                None => true,
            };
            (closed, corrupted.load(Ordering::Relaxed))
        };
        if closed {
            break;
        }
        if polluted && !rebuilt {
            rebuilt = true;
            (logger)("标准转发通道运行期检测到注入, 自动重建为兼容模式...");
            // 断开标准模式会话 (drop 即关闭), 重建兼容模式
            {
                let mut guard = state.remote_session.lock().await;
                *guard = None;
            }
            drop(session);
            let new_session = run_tunnel_session(cfg.clone(), logger.clone()).await?;
            session = new_session;
            {
                let mut guard = state.remote_session.lock().await;
                *guard = Some((session.clone(), corrupted.clone()));
            }
            (on_status)("connected");
            continue;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    // 不在此 emit "disconnected": 终态由调用方 (lib.rs 重连循环) 统一控制,
    // 否则会与重连循环的 disconnected/reconnecting 重复发射。
    Ok(())
}
