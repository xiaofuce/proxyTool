//! proxy-tool core —— SSH 隧道引擎 (纯 Rust, **无 GUI 依赖**)
//!
//! 与 GUI (src-tauri, Tauri v2) 完全解耦: GUI 通过本 crate 的公开 API 驱动隧道,
//! 事件经 `TunnelEvents` trait / `Logger` 回调发回, 发射方式由调用方决定
//! (GUI 转发到 WebView, 测试收集断言)。分层设计见 docs/重构设计.md。
//!
//! - `tunnel`: 反向隧道 (ssh -R) 引擎组装 —— 传输实现 (标准/兼容) 在 `transport`
//! - `direct`: 本地转发 (ssh -L) 与动态隧道 (ssh -D)
//! - `engine`: 隧道注册表 + 每隧道状态机任务 (L2, 重连在此)
//! - `backend`: 反向隧道的本地落地解析 (Tcp / SocksAuto: VPN 探测 + 内置 SOCKS)
//! - `ssh`: 连接/密码认证/远程执行 (三种模式共用)
//! - `socks`: 内置 SOCKS5 服务器 (连接器可插拔: Plain / 经 SSH)
//! - `presets`: 场景预设 (L3)——预设 id → TunnelSpec 模板 + 附加动作
//! - `probe`: 本机代理端口探测 (VPN 无关化)
//! - `profiles`: 服务器档案 (密码永不落盘)
//! - `store`: 档案 + 隧道列表持久化 (JSON, 路径可注入, v1→v2 迁移)
//! - `creds`: 测试/调试凭据 (环境变量或 gitignored 本地文件)

pub mod backend;
pub mod creds;
pub mod direct;
pub mod engine;
pub mod model;
pub mod presets;
pub mod probe;
pub mod profiles;
pub mod socks;
pub mod ssh;
pub mod store;
pub mod transport;
pub mod tunnel;

/// 引擎 → 外部世界的事件出口。
/// GUI 实现: 转发为 Tauri 事件 (tunnel-status / tunnel-log);
/// 测试实现: 收集到 Vec 断言事件序列。
///
/// `id` 标识隧道 (新命令面 = uuid; 旧页面适配 = 形态 tag, 见 engine::Registry::start_legacy)。
/// `kind` = 形态 tag (remote/local/dynamic), 迁移期与现有前端事件字段一一对应。
pub trait TunnelEvents: Send + Sync + 'static {
    /// 隧道状态变化。
    /// state: connecting / connected / reconnecting / disconnected / error
    fn status(&self, id: &str, kind: &str, state: &str, message: Option<&str>);
    /// 日志一行
    fn log(&self, id: &str, kind: &str, msg: &str);
}
