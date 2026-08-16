//! R9 诊断三件套: 滚动文件日志 + 内存自监控 + 诊断包导出。
//!
//! - **落盘**: `app-data/logs/app.log` (+ `.1`/`.2` 轮转, 单文件 2MB, 上限 ~6MB)
//! - **双写**: [TauriEmitter] 的 tunnel-log/tunnel-status 在发前端事件的同时写文件
//!   (前端面板 500 行环形缓冲重启即清零, 文件才是留给「事后复盘」的那份)
//! - **panic hook**: release 下 `windows_subsystem="windows"` 吞掉 stdout/stderr,
//!   不落文件 = panic 静默消失
//! - **内存自监控**: 定时把进程 RSS 写进日志 (泄漏趋势可见)
//! - **诊断包**: 环境摘要 + 全部轮转日志拼一个文本, 设置页一键导出
//!
//! 红线不变: 日志内容不含密码/口令/密钥/主机地址 (引擎日志本身就不写凭据,
//! 诊断摘要只含隧道名/形态/状态, 不含 host)。
//!
//! 结构上 [FileLog] 是可独立实例化的纯结构 (单测直接开临时目录, 不碰全局),
//! 全局 [SINK] 只是把它包了一层 —— 避免 OnceLock 让并发测试互相打架。

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::Instant,
};

/// 单文件上限 (2MB)。轮转 keep 份 → 磁盘占用上限约 6MB。
const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024;
/// 轮转保留份数: app.log.1 / app.log.2
const ROTATE_KEEP: usize = 2;
/// 单行截断阈值: 防异常巨串 (拼接事故/编码错误) 顶爆轮转。
const MAX_LINE_BYTES: usize = 64 * 1024;

static SINK: OnceLock<Mutex<FileLog>> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();

/// 滚动文件日志 (可多实例, 测试用)
struct FileLog {
    path: PathBuf,
    /// None = 当前处于轮转间隙 (句柄已关) 或打开失败 (静默降级为丢弃)
    file: Option<File>,
    written: u64,
    max_bytes: u64,
}

impl FileLog {
    /// 打开 (追加模式) 一个日志文件; 目录不存在则创建。
    fn open(dir: &Path, max_bytes: u64) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join("app.log");
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path,
            file: Some(file),
            written,
            max_bytes,
        })
    }

    fn write_line(&mut self, level: &str, tag: &str, msg: &str) {
        let mut line = format!("{} [{}] [{}] {}\n", now(), level, tag, msg);
        if line.len() > MAX_LINE_BYTES {
            line = format!(
                "{} [{}] [{}] (超长行 {}B 已截断)\n",
                now(),
                level,
                tag,
                line.len()
            );
        }
        if self.written + line.len() as u64 > self.max_bytes {
            self.rotate();
        }
        let Some(file) = self.file.as_mut() else { return };
        if file.write_all(line.as_bytes()).is_ok() {
            let _ = file.flush();
            self.written += line.len() as u64;
        }
    }

    /// 关句柄 → 删最旧 → 逐级改名 → 重开新文件。
    /// Windows 的 rename 不允许目标已存在/源被打开, 顺序不能乱。
    fn rotate(&mut self) {
        self.file = None; // 先关句柄
        let Some(name) = self.path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let nth = |n: usize| self.path.with_file_name(format!("{name}.{n}"));
        let _ = fs::remove_file(nth(ROTATE_KEEP)); // 最旧出局
        for i in (1..ROTATE_KEEP).rev() {
            let _ = fs::rename(nth(i), nth(i + 1));
        }
        let _ = fs::rename(&self.path, nth(1));
        self.file = OpenOptions::new().create(true).append(true).open(&self.path).ok();
        self.written = 0;
    }
}

fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// 初始化全局落盘日志 (app 启动时调用一次; 重复调用静默忽略)。
/// 失败 (目录不可写等) 静默降级为仅前端日志, 不阻断启动。
pub fn init(dir: &Path) {
    if SINK.get().is_some() {
        return;
    }
    let _ = START.set(Instant::now());
    let Ok(mut log) = FileLog::open(&dir.join("logs"), DEFAULT_MAX_BYTES) else {
        return;
    };
    log.write_line(
        "info",
        "app",
        &format!(
            "==== proxyTool {} 启动 | {} {} | {} ====",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
            if cfg!(debug_assertions) { "debug" } else { "release" },
        ),
    );
    if let Some(rss) = rss_bytes() {
        log.write_line("info", "mem", &format!("启动内存 RSS: {}", fmt_mb(rss)));
    }
    let _ = SINK.set(Mutex::new(log));
}

/// 写一行 (未 init / 落盘降级时静默丢弃)。同步短追加, 可在任意上下文调用。
pub fn log(level: &str, tag: &str, msg: &str) {
    let Some(sink) = SINK.get() else { return };
    let Ok(mut guard) = sink.lock() else { return };
    guard.write_line(level, tag, msg);
}

/// 进程物理内存 (RSS)。跨平台经由 memory-stats; 失败返回 None。
pub fn rss_bytes() -> Option<u64> {
    memory_stats::memory_stats().map(|m| m.physical_mem as u64)
}

pub fn fmt_mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
}

/// 运行时长 (分钟, 启动起算); 未 init 返回 0。
pub fn uptime_minutes() -> u64 {
    START.get().map(|s| s.elapsed().as_secs() / 60).unwrap_or(0)
}

/// panic hook: 落文件 + 保留原 hook 行为 (崩溃对话框等)。
/// release 的 GUI 进程无 stderr, 不装这个 panic 就是无声无息地没了。
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log("error", "panic", &info.to_string());
        prev(info);
    }));
}

/// 消息 → 文件日志级别 (与前端 logLevel 判定同语义, 保持两处观感一致)。
pub fn level_of(msg: &str) -> &'static str {
    if msg.contains('❌') || msg.contains("失败") || msg.contains("错误") || msg.contains("被拒") {
        "error"
    } else if msg.contains("警告")
        || msg.contains("WARN")
        || msg.contains("回退")
        || msg.contains("耗尽")
    {
        "warn"
    } else {
        "info"
    }
}

/// 诊断包: 环境摘要 + 全部轮转日志 (旧→新) 拼成一个文本文件。
pub fn export_bundle(logs_dir: &Path, dest: &Path, summary: &str) -> std::io::Result<()> {
    let mut out = String::new();
    out.push_str(&format!(
        "proxyTool 诊断包 v{} | 导出于 {} | 运行 {} 分钟\n\n",
        env!("CARGO_PKG_VERSION"),
        now(),
        uptime_minutes()
    ));
    out.push_str(summary);
    out.push_str("\n==== 运行日志 (旧 → 新, 已自动轮转) ====\n");
    for name in ["app.log.2", "app.log.1", "app.log"] {
        if let Ok(text) = fs::read_to_string(logs_dir.join(name)) {
            out.push_str(&format!("\n---- {name} ----\n{text}"));
        }
    }
    fs::write(dest, out)
}

/// 诊断包数量上限: 超出删最旧 (导出后调用; 诊断包单个含全部轮转日志,
/// 不清理的话反复导出会累积 —— 与日志轮转同属「磁盘占用必须有上限」)
pub fn prune_bundles(logs_dir: &Path, keep: usize) {
    let Ok(entries) = fs::read_dir(logs_dir) else { return };
    let mut bundles: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("diag-") && n.ends_with(".txt"))
        })
        .collect();
    if bundles.len() > keep {
        bundles.sort(); // 时间戳命名 (diag-YYYYMMDD-HHMMSS) → 字典序即时间序
        let excess = bundles.len() - keep;
        for old in &bundles[..excess] {
            let _ = fs::remove_file(old);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pt-diag-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn rotation_creates_and_prunes() {
        let dir = temp_dir("rotate");
        let mut log = FileLog::open(&dir, 300).unwrap();
        // 每行 ~40B, 写 60 行 → 远超 300B 上限, 必然多次轮转
        for i in 0..60 {
            log.write_line("info", "t", &format!("line-{i:04} padding-padding-padding"));
        }
        assert!(dir.join("app.log").is_file());
        assert!(dir.join("app.log.1").is_file());
        assert!(dir.join("app.log.2").is_file());
        assert!(!dir.join("app.log.3").exists(), "最旧份应被删除");
        for name in ["app.log", "app.log.1", "app.log.2"] {
            let size = fs::metadata(dir.join(name)).unwrap().len();
            assert!(size <= 300 + 80, "{name} 超出上限: {size}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bundle_contains_summary_and_lines() {
        let dir = temp_dir("bundle");
        let mut log = FileLog::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        log.write_line("info", "t", "MARKER-LIVE-LINE");
        log.write_line("error", "t", "MARKER-ERR-LINE");
        let dest = dir.join("diag-test.txt");
        export_bundle(&dir, &dest, "SUMMARY-MARKER: 3 tunnels").unwrap();
        let text = fs::read_to_string(&dest).unwrap();
        assert!(text.contains("MARKER-LIVE-LINE"));
        assert!(text.contains("MARKER-ERR-LINE"));
        assert!(text.contains("SUMMARY-MARKER"));
        assert!(text.contains("proxyTool 诊断包"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_line_truncated() {
        let dir = temp_dir("trunc");
        let mut log = FileLog::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        let huge = "x".repeat(200 * 1024);
        log.write_line("info", "t", &huge);
        let text = fs::read_to_string(dir.join("app.log")).unwrap();
        assert!(text.contains("超长行"));
        assert!(text.len() < 8 * 1024, "截断后应远小于原串: {}", text.len());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn level_of_matches_frontend_semantics() {
        assert_eq!(level_of("连接失败: 拒绝"), "error");
        assert_eq!(level_of("❌ 认证被拒"), "error");
        assert_eq!(level_of("WARN 通道耗尽, 回退独立连接"), "warn");
        assert_eq!(level_of("已连接"), "info");
    }

    #[test]
    fn prune_bundles_keeps_newest_and_ignores_other_files() {
        let dir = temp_dir("prune");
        // 5 份诊断包 + 1 个日志文件 (不应被动)
        for ts in ["20260101-000000", "20260102-000000", "20260103-000000", "20260104-000000", "20260105-000000"] {
            fs::write(dir.join(format!("diag-{ts}.txt")), "x").unwrap();
        }
        fs::write(dir.join("app.log"), "log").unwrap();
        // 同为 diag- 前缀的非包文件也按包计 (该目录本就只放包, 宽松匹配即可)
        fs::write(dir.join("diag-notes.txt"), "also matches").unwrap();
        prune_bundles(&dir, 3);
        let mut left: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .collect();
        left.sort();
        // 6 个匹配 (5 包 + notes) 排序后删最旧 3 个 → 剩 04/05/notes
        assert_eq!(
            left,
            vec![
                String::from("app.log"),
                String::from("diag-20260104-000000.txt"),
                String::from("diag-20260105-000000.txt"),
                String::from("diag-notes.txt"),
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
