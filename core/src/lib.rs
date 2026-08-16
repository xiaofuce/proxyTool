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
//! - `known_hosts`: 服务器主机密钥记忆库 (TOFU, 指纹变更 = 致命)
//! - `socks`: 内置 SOCKS5 服务器 (连接器可插拔: Plain / 经 SSH)
//! - `presets`: 场景预设 (L3)——预设 id → TunnelSpec 模板 + 附加动作
//! - `probe`: 本机代理端口探测 (VPN 无关化)
//! - `profiles`: 服务器档案
//! - `store`: 档案 + 隧道列表持久化 (JSON, 路径可注入, v1→v2 迁移)
//! - `crypto`: 落盘加密原语 (AES-256-GCM, cmd_recipes/secrets 共用)
//! - `cmd_recipes`: 命令生成页用户数据 (我的命令 + 最近输入, AES-GCM 加密落盘)
//! - `secrets`: 服务器凭据 (密码/私钥口令, 按档案 id 加密落盘 secrets.enc)
//! - `creds`: 测试/调试凭据 (环境变量或 gitignored 本地文件)

pub mod backend;
pub mod cmd_recipes;
pub mod creds;
pub mod crypto;
pub mod direct;
pub mod engine;
pub mod known_hosts;
pub mod model;
pub mod presets;
pub mod probe;
pub mod profiles;
pub mod scenarios;
pub mod secrets;
pub mod socks;
pub mod ssh;
pub mod store;
pub mod transport;
pub mod tunnel;

/// 引擎 → 外部世界的事件出口。
/// GUI 实现: 转发为 Tauri 事件 (tunnel-status / tunnel-log);
/// 测试实现: 收集到 Vec 断言事件序列。
///
/// `id` 标识隧道 (uuid); `kind` = 形态 tag (remote/local/dynamic)。
pub trait TunnelEvents: Send + Sync + 'static {
    /// 隧道状态变化。
    /// state: connecting / connected / reconnecting / disconnected / error
    fn status(&self, id: &str, kind: &str, state: &str, message: Option<&str>);
    /// 日志一行
    fn log(&self, id: &str, kind: &str, msg: &str);
}
