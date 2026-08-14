//! proxy-tool core —— SSH 隧道引擎 (纯 Rust, **无 GUI 依赖**)
//!
//! 与 GUI (src-tauri, Tauri v2) 完全解耦: GUI 通过本 crate 的公开 API 驱动隧道,
//! 事件经 `TunnelEvents` trait / `Logger` 回调发回, 发射方式由调用方决定
//! (GUI 转发到 WebView, 测试收集断言)。分层设计见 docs/重构设计.md。
//!
//! - `tunnel`: 反向隧道 (ssh -R), 含云主机安全组件兼容模式 (python3 桥接)
//! - `direct`: 本地转发 (ssh -L) 与动态隧道 (ssh -D)
//! - `ssh`: 连接/密码认证/远程执行 (三种模式共用)
//! - `socks`: 内置 SOCKS5 服务器 (连接器可插拔: Plain / 经 SSH)
//! - `probe`: 本机代理端口探测 (VPN 无关化)
//! - `profiles`: 服务器档案 (存储目录注入, 密码永不落盘)
//! - `creds`: 测试/调试凭据 (环境变量或 gitignored 本地文件)

pub mod creds;
pub mod direct;
pub mod probe;
pub mod profiles;
pub mod socks;
pub mod ssh;
pub mod tunnel;

/// 引擎 → 外部世界的事件出口。
/// GUI 实现: 转发为 Tauri 事件 (tunnel-status / tunnel-log);
/// 测试实现: 收集到 Vec 断言事件序列。
///
/// P0 阶段 kind/state 仍是字符串 (与现有前端事件格式一一对应, 见 src-tauri),
/// P3 引入隧道注册表后演进为类型化状态。
pub trait TunnelEvents: Send + Sync + 'static {
    /// 隧道状态变化。
    /// state: connecting / connected / reconnecting / disconnected / error
    fn status(&self, kind: &str, state: &str, message: Option<&str>);
    /// 日志一行
    fn log(&self, kind: &str, msg: &str);
}
