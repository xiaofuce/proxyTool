//! 服务器配置档案 (本地持久化)
//!
//! 只保存 名称/主机/端口/用户名 —— **密码永不落盘**, 每次连接时手动输入。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerProfile {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
}

/// 档案文件路径: <app_data_dir>/profiles.json
pub fn profiles_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("获取应用数据目录失败: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建数据目录失败: {e}"))?;
    Ok(dir.join("profiles.json"))
}

/// 读取档案 (文件不存在/损坏时返回空列表)
pub fn load(app: &AppHandle) -> Vec<ServerProfile> {
    let Ok(path) = profiles_path(app) else {
        return Vec::new();
    };
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// 写入档案 (整体覆盖)
pub fn save(app: &AppHandle, profiles: &[ServerProfile]) -> Result<(), String> {
    let path = profiles_path(app)?;
    let text = serde_json::to_string_pretty(profiles).map_err(|e| format!("序列化失败: {e}"))?;
    std::fs::write(path, text).map_err(|e| format!("写入配置失败: {e}"))
}
