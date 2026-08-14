//! 测试/调试用的服务器凭据。密码永不入库: 优先读环境变量, 否则读
//! `core/.test-creds.local` (该文件已被 .gitignore 忽略)。
//! 换服务器: 编辑 `.test-creds.local` (SERVER/USER/PASS/PORT, PORT 缺省 22)
//! 或 `export PROXYTOOL_TEST_SERVER/USER/PASS/PORT`。

use std::sync::OnceLock;

pub struct Creds {
    pub server: String,
    /// SSH 端口 (非标准端口服务器, 如 2222; 缺省 22)
    pub port: u16,
    pub user: String,
    pub pass: String,
}

fn read() -> Creds {
    if let (Ok(server), Ok(user), Ok(pass)) = (
        std::env::var("PROXYTOOL_TEST_SERVER"),
        std::env::var("PROXYTOOL_TEST_USER"),
        std::env::var("PROXYTOOL_TEST_PASS"),
    ) {
        let port = std::env::var("PROXYTOOL_TEST_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(22);
        return Creds {
            server,
            port,
            user,
            pass,
        };
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".test-creds.local");
    let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "未找到测试凭据 {p}: 请创建该文件 (内容 SERVER=... USER=... PASS=... [PORT=...]) \
             或设置环境变量 PROXYTOOL_TEST_SERVER/USER/PASS/PORT。读取错误: {e}",
            p = path.display()
        )
    });
    let mut server = String::new();
    let mut port: Option<u16> = None;
    let mut user = String::new();
    let mut pass = String::new();
    for line in content.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(v) = line.strip_prefix("SERVER=") {
            server = v.into();
        } else if let Some(v) = line.strip_prefix("PORT=") {
            port = v.parse().ok();
        } else if let Some(v) = line.strip_prefix("USER=") {
            user = v.into();
        } else if let Some(v) = line.strip_prefix("PASS=") {
            pass = v.into(); // 不 trim: 保留密码首尾空格, 仅去行尾换行
        }
    }
    Creds {
        server,
        port: port.unwrap_or(22),
        user,
        pass,
    }
}

static CREDS: OnceLock<Creds> = OnceLock::new();

/// 加载凭据 (首次解析, 之后复用)
pub fn load() -> &'static Creds {
    CREDS.get_or_init(read)
}

/// 便捷: 取密码 `&'static str`。测试/example 用它替代硬编码常量
pub fn pass() -> &'static str {
    load().pass.as_str()
}
