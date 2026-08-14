//! 场景预设层 (L3, 设计 §4): 预设 = TunnelSpec 模板 + 场景专属动作
//!
//! **引擎不知道任何场景**——本层只是「预设 id → 预填好的 TunnelSpec 模板 +
//! 该场景附带的动作 id」的静态表, 供 UI 向导 (P5) 取用: 选卡片 → 表单
//! (模板已预填大部分字段, 用户只改端口/目标) → tunnel_create 保存启动。
//! VPN 共享只是四个预设之一 (重构的核心诉求: 场景通用化)。

use crate::model::{Backend, ReconnectPolicy, TunnelKind, TunnelSpec};

/// 预设的静态描述 (UI 卡片数据)
pub struct Preset {
    /// 预设 id (稳定标识, 存档/向导用)
    pub id: &'static str,
    /// 名称
    pub name: &'static str,
    /// 一句话说明 (UI 卡片副标题)
    pub description: &'static str,
    /// 场景专属动作 id (UI 据此显示额外按钮; 动作实现在命令层)
    pub actions: &'static [&'static str],
}

/// 四个场景预设 (设计 §4 表格的动作列)
pub fn list() -> Vec<Preset> {
    vec![
        Preset {
            id: "vpn_share",
            name: "服务器借 VPN 出网",
            description: "反向隧道 + SOCKS: 服务器经本机 VPN 访问外网",
            actions: &["verify_internet", "deploy_wrapper"],
        },
        Preset {
            id: "expose_local",
            name: "暴露本地服务到服务器",
            description: "反向隧道 + 固定地址: 服务器上直接访问本机运行的服务",
            actions: &[],
        },
        Preset {
            id: "reach_service",
            name: "访问服务器侧服务",
            description: "本地转发: 本机端口 → 服务器侧目标 (如服务器的数据库)",
            actions: &[],
        },
        Preset {
            id: "reach_lan",
            name: "访问服务器内网",
            description: "动态隧道: 本机 SOCKS5, 服务器代连其内网任意地址",
            actions: &[],
        },
        // 从空白配置: 形态/后端全部自选 (Termius 式自由度, 不预设场景)
        Preset {
            id: "custom",
            name: "自定义",
            description: "从空白配置: 自选隧道形态 (反向/本地/动态) 与落地后端",
            actions: &[],
        },
    ]
}

/// 按预设 id 生成预填模板 (端口 0 = 服务器动态分配, 反向隧道支持)。
/// 用户在向导表单里改 name/端口/目标后经 tunnel_create 落盘。
pub fn template(preset_id: &str, name: &str, profile_id: &str) -> Result<TunnelSpec, String> {
    let kind = match preset_id {
        "vpn_share" => TunnelKind::Reverse {
            bind: "127.0.0.1".into(),
            port: 1080,
        },
        "expose_local" => TunnelKind::Reverse {
            bind: "127.0.0.1".into(),
            port: 0, // 动态分配, 冲突免扰
        },
        "reach_service" => TunnelKind::Local {
            bind: "127.0.0.1".into(),
            port: 8080,
            target_host: "127.0.0.1".into(),
            target_port: 80,
        },
        "reach_lan" => TunnelKind::Dynamic {
            bind: "127.0.0.1".into(),
            port: 1080,
        },
        // 自定义: 空白起点, 表单里切形态/改端口 (默认给反向+SocksAuto 的常用组合)
        "custom" => TunnelKind::Reverse {
            bind: "127.0.0.1".into(),
            port: 0,
        },
        _ => return Err(format!("未知预设: {preset_id}")),
    };
    let backend = match preset_id {
        // VPN 共享: 自动探测本机 VPN SOCKS, 探测不到启动内置 SOCKS (fallback 7892)
        "vpn_share" => Backend::SocksAuto {
            fallback_port: 7892,
        },
        // 暴露本地服务: 默认指向本机 web 服务, 用户在表单里改成实际端口
        "expose_local" => Backend::Tcp("127.0.0.1".into(), 3000),
        // Local/Dynamic 天然是 Tcp, 后端不参与
        _ => Backend::default(),
    };
    Ok(TunnelSpec {
        id: TunnelSpec::new_id(),
        name: name.into(),
        enabled: true,
        profile_id: profile_id.into(),
        kind,
        backend,
        policy: ReconnectPolicy::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_match_preset_kinds() {
        let (k, b) = {
            let t = template("vpn_share", "测试", "p1").unwrap();
            assert_eq!(t.policy, ReconnectPolicy::default());
            (t.kind, t.backend)
        };
        assert!(matches!(k, TunnelKind::Reverse { port: 1080, .. }));
        assert!(matches!(
            b,
            Backend::SocksAuto {
                fallback_port: 7892
            }
        ));

        let t = template("expose_local", "x", "p1").unwrap();
        assert!(matches!(t.kind, TunnelKind::Reverse { port: 0, .. }));
        assert!(matches!(t.backend, Backend::Tcp(h, 3000) if h == "127.0.0.1"));

        let t = template("reach_service", "x", "p1").unwrap();
        assert!(matches!(
            t.kind,
            TunnelKind::Local {
                target_port: 80,
                ..
            }
        ));
        assert_eq!(t.backend, Backend::default());

        let t = template("reach_lan", "x", "p1").unwrap();
        assert!(matches!(t.kind, TunnelKind::Dynamic { port: 1080, .. }));
    }

    #[test]
    fn every_preset_has_a_template() {
        for p in list() {
            let t = template(p.id, "n", "p").unwrap_or_else(|e| panic!("{e}"));
            t.validate()
                .unwrap_or_else(|e| panic!("预设 {} 的模板应直接可校验通过: {e}", p.id));
        }
    }

    #[test]
    fn unknown_preset_rejected() {
        assert!(template("nope", "n", "p").is_err());
    }
}
