//! 用户保存的场景 (「我的场景」, 设计 §4 预设层的用户侧扩展)
//!
//! 预设 (presets.rs) 是静态表; 场景是用户从向导/隧道行保存的**可复用
//! 隧道模板** = {名称, kind, backend}——不含 profile/enabled/policy
//! (创建时现场选择/叠加)。持久化在 store.rs (scenarios.json)。
//!
//! 注意: 场景专属动作 (验证外网/部署 wrapper) 由前端按**结构**判定
//! (Reverse + SocksAuto), 与来源无关, 故模型无需 actions 字段。

use serde::{Deserialize, Serialize};

use crate::model::{Backend, TunnelKind};

/// 用户保存的场景 (向导「我的场景」卡片)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Scenario {
    /// uuid (前端生成或后端补)
    pub id: String,
    /// 场景名
    pub name: String,
    /// 一句话说明 (UI 卡片副标题; 空则保存时由 `describe()` 回填)
    #[serde(default)]
    pub description: String,
    /// 隧道形态 (创建隧道时直接克隆)
    pub kind: TunnelKind,
    /// 落地后端 (反向隧道用)
    #[serde(default)]
    pub backend: Backend,
}

impl Scenario {
    /// kind + backend → 中文摘要 (卡片副标题/向导 hint)
    pub fn describe(&self) -> String {
        match &self.kind {
            TunnelKind::Reverse { port, .. } => match &self.backend {
                Backend::SocksAuto { fallback_port } => format!(
                    "反向 → 本机 SOCKS (自动探测 VPN, 备用 {fallback_port}); 服务器端口 {port}{}",
                    if *port == 0 { " (动态分配)" } else { "" }
                ),
                Backend::Tcp(host, lport) => format!(
                    "反向 → 本机 {host}:{lport}; 服务器端口 {port}{}",
                    if *port == 0 { " (动态分配)" } else { "" }
                ),
            },
            TunnelKind::Local {
                port,
                target_host,
                target_port,
                ..
            } => format!("本地 → 本机 :{port} → {target_host}:{target_port}"),
            TunnelKind::Dynamic { port, .. } => format!("动态 → 本机 SOCKS5 :{port} (访问服务器内网)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_covers_all_shapes() {
        let vpn = Scenario {
            id: "s1".into(),
            name: "n".into(),
            description: String::new(),
            kind: TunnelKind::Reverse {
                bind: "127.0.0.1".into(),
                port: 1080,
            },
            backend: Backend::SocksAuto {
                fallback_port: 7892,
            },
        };
        assert!(vpn.describe().contains("SOCKS"), "{}", vpn.describe());
        assert!(vpn.describe().contains("7892"));

        let expose = Scenario {
            kind: TunnelKind::Reverse {
                bind: "127.0.0.1".into(),
                port: 0,
            },
            backend: Backend::Tcp("127.0.0.1".into(), 3000),
            ..vpn.clone()
        };
        assert!(expose.describe().contains("3000"));
        assert!(expose.describe().contains("动态分配"), "port 0 应标注动态分配");

        let local = Scenario {
            kind: TunnelKind::Local {
                bind: "127.0.0.1".into(),
                port: 8080,
                target_host: "db.internal".into(),
                target_port: 5432,
            },
            backend: Backend::default(),
            ..vpn.clone()
        };
        assert!(local.describe().contains("db.internal:5432"));

        let dynamic = Scenario {
            kind: TunnelKind::Dynamic {
                bind: "127.0.0.1".into(),
                port: 1080,
            },
            backend: Backend::default(),
            ..vpn
        };
        assert!(dynamic.describe().contains("SOCKS5"));
    }

    /// 场景 JSON 往返: camelCase 字段契约 (前端/落盘一致)
    #[test]
    fn scenario_json_roundtrip() {
        let s = Scenario {
            id: "s1".into(),
            name: "实验室借网".into(),
            description: String::new(),
            kind: TunnelKind::Local {
                bind: "127.0.0.1".into(),
                port: 18765,
                target_host: "127.0.0.1".into(),
                target_port: 2222,
            },
            backend: Backend::default(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"targetHost\""), "应为 camelCase: {json}");
        let back: Scenario = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
        // 缺 description/backend 的旧文件 → 默认值填充
        let partial = json.replace("\"backend\":\"socksAuto\"", "");
        let _ok: Scenario = serde_json::from_str(&partial).unwrap_or_else(|e| panic!("{e}"));
    }
}
