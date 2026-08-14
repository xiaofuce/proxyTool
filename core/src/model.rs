//! 隧道数据模型与类型化错误 (设计文档 §3.2/§3.3/§3.4)
//!
//! - `TunnelSpec` 等: 隧道作为一等实体 (frp 骨架) —— 用户可见、可持久化
//!   (serde, 存 store.rs 的 tunnels.json), 每条隧道一个 uuid。
//! - `TunnelError` 是重连策略的类型载体: 重连循环按 `retryable()` 决策
//!   (致命错误立即停止并报错, 不进退避), 取代旧版字符串匹配 `is_auth_rejected`。

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Duration 以「秒 (u64)」形式入 JSON, 避免 serde 对 Duration 的默认行为
mod secs_duration {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}

/// 一条隧道 = 用户可见、可持久化的实体 (设计 §3.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelSpec {
    /// uuid, 重启恢复用
    pub id: String,
    /// 用户命名, 如 "服务器借VPN出网"
    pub name: String,
    /// frp 同款: 开关但不删配置 (false = 不随应用启动)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 关联的服务器档案 (密码永不落盘, 仅档案引用)
    pub profile_id: String,

    pub kind: TunnelKind,
    /// 隧道「另一端」指向什么 (反向隧道专用; Local/Dynamic 天然是 Tcp)
    #[serde(default)]
    pub backend: Backend,
    #[serde(default)]
    pub policy: ReconnectPolicy,
}

fn default_true() -> bool {
    true
}

/// 隧道形态 (对应 ssh -R / -L / -D)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum TunnelKind {
    /// ssh -R: 服务器监听 bind:port →(经隧道)→ 本机 backend。
    /// port = 0 表示由服务器动态分配 (P4: 实际端口回填到隧道详情)
    Reverse {
        /// "127.0.0.1" | "*" (* = 服务器外网可见, 需 sshd GatewayPorts)
        bind: String,
        port: u16,
    },
    /// ssh -L: 本机监听 bind:port →(经隧道)→ 服务器侧 target
    Local {
        bind: String,
        port: u16,
        target_host: String,
        target_port: u16,
    },
    /// ssh -D: 本机 SOCKS5 → 服务器代连任意目标 (访问服务器内网)
    Dynamic { bind: String, port: u16 },
}

impl TunnelKind {
    /// 稳定的形态标识 (注册表/事件/前端共用; 与旧 kind 字段 "remote"/"local"/"dynamic" 对应)
    pub fn tag(&self) -> &'static str {
        match self {
            TunnelKind::Reverse { .. } => "remote",
            TunnelKind::Local { .. } => "local",
            TunnelKind::Dynamic { .. } => "dynamic",
        }
    }
}

/// 本地端后端: 反向隧道的流量落地处 (frp 插件思想的简化版)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Backend {
    /// 落到固定本机地址, 如暴露本地 web: ("127.0.0.1", 3000)
    Tcp(String, u16),
    /// 落到本机 SOCKS: 自动探测 VPN 端口, 探测不到启动内置 SOCKS5
    /// (现 resolve_local_proxy 逻辑; fallback_port = 内置 SOCKS 的监听端口)
    SocksAuto { fallback_port: u16 },
}

impl Default for Backend {
    fn default() -> Self {
        Backend::SocksAuto {
            fallback_port: 1080,
        }
    }
}

/// 重连与保活策略 (设计 §3.5: 融合 autossh + frp + rathole)。
/// P3 仅消费 `auto`; fast_retries/alive_reset 由 P4 重连引擎消费。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReconnectPolicy {
    /// 自动重连开关 (页面「自动重连」复选框的归宿)
    pub auto: bool,
    /// frp FastBackoff: 断线先 N×1s 快速重试 (P4)
    pub fast_retries: u32,
    /// 指数退避封顶 (1→2→…→此值)
    #[serde(with = "secs_duration")]
    pub max_backoff: Duration,
    /// rathole: 存活超过此时长 → 退避计数归零 (防 flappy 连接被退避惩罚) (P4)
    #[serde(with = "secs_duration")]
    pub alive_reset: Duration,
    /// russh keepalive_interval
    #[serde(with = "secs_duration")]
    pub keepalive: Duration,
    /// russh keepalive_max (判死时延 = keepalive × max, 显式化)
    pub keepalive_max: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            auto: true,
            fast_retries: 3,
            max_backoff: Duration::from_secs(30),
            alive_reset: Duration::from_secs(3),
            keepalive: Duration::from_secs(10),
            keepalive_max: 3,
        }
    }
}

/// 单条隧道的状态机 (设计 §3.3, 替代裸字符串)。
/// Clone/PartialEq: 注册表查询/快照与事件断言用; 错误只保留面向用户的
/// message + retryable (类型化错误在决策点已完成使命, russh::Error 不可克隆)。
///
/// ```text
/// Stopped ──start()──▶ Starting ──会话建立+转发就绪──▶ Running
///    ▲                    │                              │
///    │                    ├─ Err(致命) ─────────────▶ Failed
///    │                    │                              │
///    └──stop()────────────┴── Err(可重试) ──▶ Backoff{n} ─┘
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum TunnelState {
    /// 未运行
    Stopped,
    /// 建立中 (连接/认证/转发建立)
    Starting,
    /// 会话建立且转发就绪
    Running,
    /// 断线退避中 (第 attempt 次重试, wait_secs 后重试)
    Backoff { attempt: u32, wait_secs: u64 },
    /// 致命错误停止 (重连无法解决; message 面向用户)
    Failed { message: String, retryable: bool },
}

impl TunnelSpec {
    /// 生成新 spec 的 uuid
    pub fn new_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// 校验不变量 (rathole 式: 读取后 validate, 默认值已在 serde 层填充)
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("隧道名称不能为空".into());
        }
        if self.profile_id.trim().is_empty() {
            return Err("未关联服务器档案".into());
        }
        let bind = match &self.kind {
            TunnelKind::Reverse { bind, .. } => bind,
            TunnelKind::Local {
                bind, target_host, ..
            } => {
                if target_host.trim().is_empty() {
                    return Err("目标地址不能为空".into());
                }
                bind
            }
            TunnelKind::Dynamic { bind, .. } => bind,
        };
        if bind.trim().is_empty() {
            return Err("监听地址不能为空".into());
        }
        Ok(())
    }
}

/// 隧道/SSH 操作的类型化错误。
/// 每个变体携带最小决策上下文 (端口/地址/原因), Display 面向用户。
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// TCP/SSH 连接建立失败 (网络不可达 / 拒绝 / 超时 / DNS) —— 可重试
    #[error("SSH 连接 {addr} 失败: {source}")]
    Connect {
        addr: String,
        #[source]
        source: russh::Error,
    },

    /// 服务器明确拒绝认证 (密码错误 / 私钥未被服务器接受) —— 重连无法解决, 立即停止
    #[error("认证被拒绝 (请检查用户名/密码, 或私钥是否已加入服务器 authorized_keys)")]
    AuthRejected,

    /// 私钥文件加载失败 (不存在/格式错误/口令不对) —— 配置错误, 立即停止
    #[error("加载私钥 {path} 失败: {reason}")]
    KeyLoad { path: String, reason: String },

    /// 认证阶段的通信失败 (网络中断等, 与「密码错误」区分) —— 可重试:
    /// 宁可多试不误停 (旧版哲学保持)
    #[error("认证失败: {source}")]
    AuthIo {
        #[source]
        source: russh::Error,
    },

    /// 本机监听端口绑定失败 (被占用/无权限) —— 重连无法解决, 立即停止
    /// (OpenSSH ExitOnForwardFailure 语义: 转发建立失败 = 致命)
    #[error("绑定本机监听端口 {port} 失败: {reason}")]
    PortInUse { port: u16, reason: String },

    /// 服务器拒绝反向端口转发请求 (sshd AllowTcpForwarding=no / 端口被占等) —— 立即停止
    #[error("服务器拒绝反向端口转发 {port}: {reason}")]
    ForwardRejected { port: u32, reason: String },

    /// SSH 通道打开失败 (会话通道 / direct_tcpip / 探测通道) —— 可重试
    #[error("打开{what}失败: {reason}")]
    ChannelOpen { what: String, reason: String },

    /// 协议/探测失败 (转发端口探测不可达、命令执行失败等) —— 可重试。
    /// 反向隧道的标准模式探测失败还会触发兼容模式回退 (tunnel.rs::run_tunnel)
    #[error("{0}")]
    Protocol(String),

    /// 会话运行期错误 (读写断开等) —— 可重试 (网络掉线的主形态)
    #[error("SSH 会话错误: {source}")]
    Session {
        #[source]
        source: russh::Error,
    },

    /// 服务器主机密钥指纹与记忆不符 (known_hosts TOFU 校验失败) —— 立即停止:
    /// 重连无意义, 且可能是中间人攻击; 服务器确已重装时由用户清除记录后重连。
    #[error("服务器 {host} 主机密钥指纹已变更 (预期 {expected}, 实际 {actual}) —— 若服务器确已重装, 请在「服务器」页清除指纹记录后重试")]
    HostKeyChanged {
        host: String,
        expected: String,
        actual: String,
    },

    /// 用户主动断开 —— 静默停止, 不报错不重连。
    /// (P4 重连引擎引入: 现阶段断开意图经 disconnect_intent 标志传递)
    #[error("已取消")]
    Cancelled,
}

impl TunnelError {
    /// 重连是否可能解决该错误。
    /// false = 致命: 重连循环立即停止 (GATETIME 语义: 首连致命错误不进退避)。
    /// 分类哲学: 拿不准的归 true —— 宁可多试不误停 (P1 计划风险条目)。
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            TunnelError::Connect { .. }
                | TunnelError::AuthIo { .. }
                | TunnelError::ChannelOpen { .. }
                | TunnelError::Protocol(_)
                | TunnelError::Session { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 锁住 retryable 分类契约: 重连循环 (run_with_reconnect) 的停止/重试决策完全依赖它
    #[test]
    fn retryable_classification() {
        // 可重试: 网络类
        let connect = TunnelError::Connect {
            addr: "1.2.3.4:22".into(),
            source: russh::Error::UnknownKey,
        };
        let auth_io = TunnelError::AuthIo {
            source: russh::Error::UnknownKey,
        };
        let channel = TunnelError::ChannelOpen {
            what: "会话通道".into(),
            reason: "closed".into(),
        };
        let protocol = TunnelError::Protocol("转发端口探测失败".into());
        let session = TunnelError::Session {
            source: russh::Error::UnknownKey,
        };
        for e in [&connect, &auth_io, &channel, &protocol, &session] {
            assert!(e.retryable(), "{e} 应可重试");
        }

        // 致命: 配置类 (重试无法解决)
        let auth_rejected = TunnelError::AuthRejected;
        let port_in_use = TunnelError::PortInUse {
            port: 1080,
            reason: "Addr in use".into(),
        };
        let forward_rejected = TunnelError::ForwardRejected {
            port: 1081,
            reason: "administratively prohibited".into(),
        };
        let host_key_changed = TunnelError::HostKeyChanged {
            host: "1.2.3.4:22".into(),
            expected: "SHA256:aaa".into(),
            actual: "SHA256:bbb".into(),
        };
        let key_load = TunnelError::KeyLoad {
            path: "C:/k/id_ed25519".into(),
            reason: "invalid format".into(),
        };
        let cancelled = TunnelError::Cancelled;
        for e in [
            &auth_rejected,
            &port_in_use,
            &forward_rejected,
            &host_key_changed,
            &key_load,
            &cancelled,
        ] {
            assert!(!e.retryable(), "{e} 应为致命 (停止重连)");
        }
    }

    /// Display 面向用户: 关键上下文 (地址/端口/原因) 不丢失
    #[test]
    fn display_carries_context() {
        let e = TunnelError::PortInUse {
            port: 1080,
            reason: "Addr in use".into(),
        };
        assert!(e.to_string().contains("1080"), "端口应出现在错误信息: {e}");
        assert!(
            e.to_string().contains("Addr in use"),
            "原因应出现在错误信息: {e}"
        );

        let e = TunnelError::Connect {
            addr: "1.2.3.4:22".into(),
            source: russh::Error::UnknownKey,
        };
        assert!(e.to_string().contains("1.2.3.4:22"), "地址应出现: {e}");
    }

    /// VPN 共享场景的 spec: JSON 往返 (tunnels.json 持久化的基础)
    #[test]
    fn spec_json_roundtrip() {
        let spec = TunnelSpec {
            id: "id-1".into(),
            name: "服务器借VPN出网".into(),
            enabled: true,
            profile_id: "p1".into(),
            kind: TunnelKind::Reverse {
                bind: "127.0.0.1".into(),
                port: 1081,
            },
            backend: Backend::SocksAuto {
                fallback_port: 1080,
            },
            policy: ReconnectPolicy::default(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        // camelCase: 前端/JSON 字段名契约
        assert!(json.contains("\"profileId\""), "应输出 camelCase: {json}");
        let back: TunnelSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, spec.kind);
        assert_eq!(back.backend, spec.backend);
        assert_eq!(back.policy, spec.policy);
    }

    /// 部分 JSON (旧文件/手工编辑): 默认值填充 (rathole 式)
    #[test]
    fn spec_partial_json_gets_defaults() {
        // 缺 enabled/backend/policy
        let json = r#"{
            "id": "x", "name": "n", "profileId": "p",
            "kind": { "dynamic": { "bind": "127.0.0.1", "port": 1080 } }
        }"#;
        let spec: TunnelSpec = serde_json::from_str(json).unwrap();
        assert!(spec.enabled, "enabled 默认 true");
        assert_eq!(spec.backend, Backend::default());
        assert_eq!(spec.policy, ReconnectPolicy::default());
        // Duration 入 JSON 为整数秒
        let policy_json = serde_json::to_string(&spec.policy).unwrap();
        assert!(policy_json.contains("\"maxBackoff\":30"), "{policy_json}");
    }

    /// ReconnectPolicy 默认值 = 设计 §3.5 (frp 3×快试 / rathole 3s 重置 / autossh 保活)
    #[test]
    fn reconnect_policy_defaults() {
        let p = ReconnectPolicy::default();
        assert!(p.auto);
        assert_eq!(p.fast_retries, 3);
        assert_eq!(p.max_backoff, Duration::from_secs(30));
        assert_eq!(p.alive_reset, Duration::from_secs(3));
        assert_eq!(p.keepalive, Duration::from_secs(10));
        assert_eq!(p.keepalive_max, 3);
    }

    /// validate: 关键不变量
    #[test]
    fn spec_validate_rejects_bad_input() {
        let mut spec = TunnelSpec {
            id: "x".into(),
            name: "n".into(),
            enabled: true,
            profile_id: "p".into(),
            kind: TunnelKind::Reverse {
                bind: "127.0.0.1".into(),
                port: 1081,
            },
            backend: Backend::SocksAuto {
                fallback_port: 1080,
            },
            policy: ReconnectPolicy::default(),
        };
        assert!(spec.validate().is_ok());
        // port 0 = 服务器动态分配 (P4), 合法
        spec.kind = TunnelKind::Reverse {
            bind: "127.0.0.1".into(),
            port: 0,
        };
        assert!(spec.validate().is_ok());
        spec.kind = TunnelKind::Reverse {
            bind: String::new(),
            port: 1081,
        };
        assert!(spec.validate().is_err(), "空 bind 应报错");
        spec.kind = TunnelKind::Reverse {
            bind: "127.0.0.1".into(),
            port: 1081,
        };
        spec.name = "  ".into();
        assert!(spec.validate().is_err(), "空白名应报错");
        spec.name = "n".into();
        spec.profile_id = String::new();
        assert!(spec.validate().is_err(), "缺档案应报错");
    }

    /// kind → tag 映射 (与旧前端 kind 字段对应, 迁移期事件流不变)
    #[test]
    fn kind_tag_matches_legacy_kind() {
        let rev = TunnelKind::Reverse {
            bind: "127.0.0.1".into(),
            port: 1,
        };
        let loc = TunnelKind::Local {
            bind: "127.0.0.1".into(),
            port: 1,
            target_host: "h".into(),
            target_port: 1,
        };
        let dyn_ = TunnelKind::Dynamic {
            bind: "127.0.0.1".into(),
            port: 1,
        };
        assert_eq!(rev.tag(), "remote");
        assert_eq!(loc.tag(), "local");
        assert_eq!(dyn_.tag(), "dynamic");
    }
}
