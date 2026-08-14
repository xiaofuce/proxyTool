//! 隧道数据模型与类型化错误 (设计文档 §3.4)
//!
//! `TunnelError` 是重连策略的类型载体: 重连循环按 `retryable()` 决策
//! (致命错误立即停止并报错, 不进退避), 取代旧版字符串匹配 `is_auth_rejected`。
//! P3 将在本模块继续落地 `TunnelSpec / TunnelKind / Backend / ReconnectPolicy / TunnelState`。

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

    /// 服务器明确拒绝密码认证 —— 重连无法解决, 立即停止
    #[error("密码认证被拒绝 (请检查用户名/密码)")]
    AuthRejected,

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
    use super::TunnelError;

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
        let cancelled = TunnelError::Cancelled;
        for e in [&auth_rejected, &port_in_use, &forward_rejected, &cancelled] {
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
}
