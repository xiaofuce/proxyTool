//! 持久化 (设计 §3.8): 档案 + 隧道列表, JSON, 路径可注入
//!
//! - `tunnels.json`: `Vec<TunnelSpec>` (密码永不落盘, 仅档案引用)
//! - `profiles.json` v2: `{version, defaults, profiles}` —— ssh_config 式分层
//!   (全局默认 + 每档案覆盖)。v1 (裸数组, 现状 profiles.rs 写出的格式)
//!   读取时自动迁移, 旧档案无损带入; defaults 为全局默认值层。
//!
//! 读取后默认值填充由 serde `#[serde(default)]` 完成 (rathole 式);
//! 目录由调用方注入: GUI 传 app_data_dir, 测试传 tempdir。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::TunnelSpec;
use crate::profiles::ServerProfile;

/// profiles.json 当前版本
pub const PROFILES_VERSION: u32 = 2;

/// 全局默认值层 (所有档案共享, 单条档案可覆盖)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDefaults {
    /// 连接超时 (秒); None = 引擎内置默认 (10s)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u32>,
    /// 重连策略默认 (隧道 spec 未显式给定时兜底); None = ReconnectPolicy::default
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconnect: Option<crate::model::ReconnectPolicy>,
}

/// profiles.json v2 结构
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileStore {
    pub version: u32,
    #[serde(default)]
    pub defaults: ProfileDefaults,
    #[serde(default)]
    pub profiles: Vec<ServerProfile>,
}

fn create_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("创建数据目录失败: {e}"))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| format!("序列化失败: {e}"))?;
    // 先写临时文件再原子改名, 避免写一半崩溃损坏配置
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("写入配置失败: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("替换配置失败: {e}"))
}

// ---------- tunnels.json ----------

pub fn tunnels_path(dir: &Path) -> Result<PathBuf, String> {
    create_dir(dir)?;
    Ok(dir.join("tunnels.json"))
}

/// 读取隧道列表 (文件不存在/损坏时返回空列表, 不阻断启动)
pub fn load_tunnels(dir: &Path) -> Vec<TunnelSpec> {
    let Ok(path) = tunnels_path(dir) else {
        return Vec::new();
    };
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// 写入隧道列表 (整体覆盖, 原子替换)
pub fn save_tunnels(dir: &Path, tunnels: &[TunnelSpec]) -> Result<(), String> {
    let path = tunnels_path(dir)?;
    write_json(&path, &tunnels)
}

// ---------- profiles.json (v2 + 迁移) ----------

pub fn profiles_path(dir: &Path) -> Result<PathBuf, String> {
    create_dir(dir)?;
    Ok(dir.join("profiles.json"))
}

/// 读取档案 (v2 结构)。
/// v1 (裸数组) 自动迁移: 转成 v2 返回 (调用方决定是否立即落盘, 见 `migrate_needed`)。
/// 文件不存在 → 空 store; 损坏 → 空 store (不阻断启动, 与 profiles.rs 旧语义一致)。
pub fn load_profiles(dir: &Path) -> ProfileStore {
    let Ok(path) = profiles_path(dir) else {
        return empty_store();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return empty_store();
    };
    // 先按 v2 解 (带版本字段); 失败再按 v1 裸数组解 → 迁移
    if let Ok(store) = serde_json::from_str::<ProfileStore>(&text) {
        return store;
    }
    match serde_json::from_str::<Vec<ServerProfile>>(&text) {
        Ok(profiles) => ProfileStore {
            version: PROFILES_VERSION,
            defaults: ProfileDefaults::default(),
            profiles,
        },
        Err(_) => empty_store(),
    }
}

/// 档案文件是否仍是 v1 (裸数组) —— load 后据此决定是否立即回写完成迁移
pub fn migrate_needed(dir: &Path) -> bool {
    let Ok(path) = profiles_path(dir) else {
        return false;
    };
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str::<ProfileStore>(&text).is_err(),
        Err(_) => false,
    }
}

/// 写入档案 (v2 结构, 原子替换)
pub fn save_profiles(dir: &Path, store: &ProfileStore) -> Result<(), String> {
    let path = profiles_path(dir)?;
    write_json(&path, store)
}

fn empty_store() -> ProfileStore {
    ProfileStore {
        version: PROFILES_VERSION,
        defaults: ProfileDefaults::default(),
        profiles: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Backend, ReconnectPolicy, TunnelKind};

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pt-store-test-{}", TunnelSpec::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_spec() -> TunnelSpec {
        TunnelSpec {
            id: "t1".into(),
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
        }
    }

    /// tunnels.json 往返; 文件不存在 → 空列表
    #[test]
    fn tunnels_roundtrip_and_missing() {
        let dir = tempdir();
        assert!(load_tunnels(&dir).is_empty(), "无文件应返回空");

        save_tunnels(&dir, &[sample_spec()]).unwrap();
        let loaded = load_tunnels(&dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "服务器借VPN出网");
        assert_eq!(loaded[0].kind, sample_spec().kind);

        // 损坏文件 → 空列表 (不 panic)
        std::fs::write(tunnels_path(&dir).unwrap(), "{broken").unwrap();
        assert!(load_tunnels(&dir).is_empty());
    }

    /// profiles v1 (裸数组, 旧版 profiles.rs 写出的格式) → v2 迁移无损
    #[test]
    fn profiles_v1_migrates_losslessly() {
        let dir = tempdir();
        let v1 = r#"[{"id":"p1","name":"测试机","host":"1.2.3.4","port":22,"username":"tester"}]"#;
        std::fs::write(profiles_path(&dir).unwrap(), v1).unwrap();
        assert!(migrate_needed(&dir), "v1 文件应报告需要迁移");

        let store = load_profiles(&dir);
        assert_eq!(store.version, PROFILES_VERSION);
        assert_eq!(store.profiles.len(), 1);
        assert_eq!(store.profiles[0].host, "1.2.3.4");
        assert_eq!(store.profiles[0].username, "tester");

        // 落盘后不再需要迁移, 且往返无损
        save_profiles(&dir, &store).unwrap();
        assert!(!migrate_needed(&dir));
        let again = load_profiles(&dir);
        assert_eq!(again.profiles.len(), 1);
        assert_eq!(again.profiles[0].name, "测试机");
    }

    /// v2 文件直接读; defaults 层往返
    #[test]
    fn profiles_v2_roundtrip_with_defaults() {
        let dir = tempdir();
        let store = ProfileStore {
            version: PROFILES_VERSION,
            defaults: ProfileDefaults {
                connect_timeout_secs: Some(15),
                reconnect: None,
            },
            profiles: vec![ServerProfile {
                id: "p1".into(),
                name: "n".into(),
                host: "h".into(),
                port: 22,
                username: "u".into(),
                identity_file: Some("C:/keys/id_ed25519".into()),
            }],
        };
        save_profiles(&dir, &store).unwrap();
        assert!(!migrate_needed(&dir));
        let back = load_profiles(&dir);
        assert_eq!(back.defaults.connect_timeout_secs, Some(15));
        assert_eq!(back.profiles.len(), 1);
        assert_eq!(
            back.profiles[0].identity_file.as_deref(),
            Some("C:/keys/id_ed25519"),
            "私钥路径应往返无损"
        );
    }

    /// 文件不存在 → 空 store (不报错)
    #[test]
    fn profiles_missing_is_empty() {
        let dir = tempdir();
        let store = load_profiles(&dir);
        assert!(store.profiles.is_empty());
        assert_eq!(store.version, PROFILES_VERSION);
    }
}
