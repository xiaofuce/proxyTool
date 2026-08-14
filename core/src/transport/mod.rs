//! 反向隧道的传输层 (P2)
//!
//! 传输 = 「建立服务器侧监听, 并把到来的连接桥接到本地 SOCKS」的机制,
//! 两种实现 (设计 §3.6):
//! - **标准模式** `russh_direct`: sshd 原生 `tcpip_forward` 转发通道
//! - **兼容模式** `python_bridge`: 会话通道 + 服务器端 python3 桥接助手,
//!   帧协议复用单通道 (云主机安全组件注入 sshd 转发通道时的回退路径)
//!
//! 公共接口: 两实现各暴露同签名函数
//! `establish(cfg, logger) -> Result<(TunnelSession, u16), TunnelError>`
//! —— 返回会话 + 服务器实际监听端口 (`remote_port=0` 动态分配时两者不同,
//! 标准 = tcpip_forward 回告值, 兼容 = 助手 PORT 行上报)。
//! (未做成形式 trait —— 引擎 run_tunnel 以 match 显式选择, 无 dyn 泛化需求;
//! 污染探测 (首字节 0x00) 的探测与判定都在实现内部, 引擎不感知模式差异)。
//!
//! - `frame`: 兼容模式的帧协议编解码 (标记帧/CRC32/分块/注入同步),
//!   纯逻辑、独立单测 (P2a)。

pub mod frame;
pub mod python_bridge;
pub mod russh_direct;
