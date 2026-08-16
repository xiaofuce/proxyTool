# proxyTool

**中文** | [English](#english)

一键建立「本地电脑 ⇄ 远程服务器」的 SSH 隧道，并可视化地管理它们。

所有操作在本地完成，只需要远程服务器的账号密码（或私钥）。密码以 AES-256-GCM **密文**保存在本机，重启 / 开机自启免重输。

## 它解决什么问题

| 你想做的事 | 隧道形态 | 等价命令 |
|---|---|---|
| 让**服务器**借用**本机**的网络出口上外网（本机挂了代理/VPN，服务器出不了网） | 反向隧道 | `ssh -R` |
| 在**本机**访问**服务器上/服务器内网**的服务（远程数据库、内网 Web） | 本地转发 | `ssh -L` |
| 把服务器当作**本机的 SOCKS5 代理**，访问它内网的任意主机 | 动态隧道 | `ssh -D` |

反向隧道内置本机代理端口自动探测（也支持内置 SOCKS 兜底），不绑定任何特定 VPN 客户端。

## 功能特性

**隧道引擎**（`core/`，纯 Rust crate，零 GUI 依赖）
- 隧道是一等实体：多条并存、持久化、开机自启，托盘常驻后台
- 自动重连：快速重试 → 指数退避封顶；存活后计数归零；可手动立即重试
- `-R 0` 动态端口分配，实际端口自动回填保存
- **同档案共享连接**：同一服务器的多条隧道复用一条 SSH 连接（N 条隧道 1 次认证），带 MaxSessions 预算准入与超限自动回退独立连接
- **注入型 sshd 兼容**：部分云主机安全组件会向转发通道注入审计数据导致标准转发损坏——自动检测并切换为会话通道 + 服务器侧转发助手的兼容模式，无需人工干预
- 主机密钥 TOFU 校验（首连记住、变更即拒绝），密码 / 私钥双认证

**安全**
- SSH 密码 / 私钥口令仅以 AES-256-GCM 密文落盘（`secrets.enc` + 本机密钥文件），明文不落任何日志与配置
- 诚实的威胁模型：密钥与密文同机存放，防的是「顺手翻文件 / grep」，不防御本机已被入侵的对手
- 主机指纹变更 = 致命错误不重连，UI 提供信任 / 清除路径

**界面**（Tauri v2，三栏 Termius 式布局）
- 服务器为主角：中列服务器块 + 右列多态详情面板；块上 ▶ 一键启停该服务器全部隧道
- 隧道行五态徽章 / 端口 / uptime / 惰性 ⋯ 菜单（重试、验证外网、部署 proxy、存为场景…）
- 明暗双主题、字号三档、**中英双语**（设置内切换）
- 命令生成页：服务器↔服务器场景一键生成 `ssh` / `autossh` 命令并解释每个参数；「我的命令」命名保存
- 帮助页：三形态图解 + 真实场景对照 + FAQ
- 全部反馈走应用内 toast / dialog，零原生弹窗

## 快速上手

1. **添加服务器**：服务器页 → 新建，填地址 / 端口 / 用户名（密码首次启动时输入，可选记住）
2. **建隧道**：选服务器 → 新建隧道 → 选场景预设（如「VPN 共享」「访问内网服务」）或空白自定义
3. **启动**：点服务器块的 ▶ 一键启动全部启用中的隧道；关窗 = 收进托盘常驻

## 从源码构建

环境要求：[Rust](https://rustup.rs/)、Node.js ≥ 18、[Tauri v2 依赖](https://v2.tauri.app/start/prerequisites/)

```bash
npm install
npm run tauri dev     # 开发模式
npm run tauri build   # 产出安装包 (Windows: msi/nsis; macOS: app/dmg)
```

## 测试

```bash
cargo test -p proxy-tool-core                        # 全部
cargo test -p proxy-tool-core --test e2e_tunnel -- --test-threads=1   # 端到端 (须串行)
```

端到端用例需要一台真实 SSH 服务器：复制 `core/.test-creds.local.example` 为 `core/.test-creds.local`（已被 gitignore 忽略）填入地址与密码，或设置环境变量 `PROXYTOOL_TEST_SERVER / USER / PASS / PORT`。**真实凭据永不入库。**

## 项目结构

```
core/        隧道引擎 (纯 Rust): engine/ 注册表+状态机, transport/ 标准与兼容两种传输,
             direct/ -L 与 -D, pool/ 共享连接, secrets/ 凭据加密, known_hosts/ TOFU
src-tauri/   Tauri GUI 桥接: 命令面 + 事件桥 + 托盘/自启
src/         前端 (TypeScript, 无框架): main/ui/theme/icons/i18n
docs/        设计文档与重构记录
```

## 文档

- [设计文档（调研结论）](docs/设计文档-调研结论.md)
- [重构设计](docs/重构设计.md) / [重构计划](docs/重构计划.md)

---

# English

**[中文](#proxytool)** | English

One-click SSH tunnels between your local machine and remote servers — with a visual manager on top.

Everything runs locally; all you need is the remote server's credentials (password or key). Passwords are stored **encrypted** (AES-256-GCM) on your machine, so restarts and autostart never prompt again.

## What it solves

| Goal | Tunnel type | Equivalent |
|---|---|---|
| Let a **server** reach the internet through **your machine's** proxy/VPN | Reverse | `ssh -R` |
| Access services **on the server / in its intranet** from your machine (remote DB, internal web) | Local | `ssh -L` |
| Use the server as a **SOCKS5 proxy** for your machine, reaching any host in its network | Dynamic | `ssh -D` |

The reverse tunnel auto-detects your local proxy port (with a built-in SOCKS fallback) — vendor-agnostic, works with any VPN client.

## Features

**Engine** (`core/`, pure Rust crate, zero GUI dependencies)
- Tunnels are first-class entities: multiple concurrent, persisted, autostart, tray-resident
- Auto-reconnect: fast retries → capped exponential backoff; counter resets after a stable connection; manual retry-now
- `-R 0` dynamic port allocation, actual port backfilled and persisted
- **Shared connections per server**: N tunnels over one SSH connection (one authentication), with MaxSessions budget admission and automatic fallback to dedicated connections
- **Injected-sshd compatibility**: some cloud security agents corrupt standard forwarding by injecting audit bytes — detected automatically, switching to a session-channel + server-side helper mode with no manual intervention
- Host-key TOFU verification (trust on first use, reject on change); password and key auth

**Security**
- SSH passwords / key passphrases are only persisted as AES-256-GCM ciphertext (`secrets.enc` + local key file); never in plaintext logs or configs
- Honest threat model: key lives on the same machine — this protects against casual snooping/grep, not a compromised host
- Host key change = fatal, no retry; UI offers trust / clear paths

**UI** (Tauri v2, three-pane Termius-style layout)
- Servers front and center: server blocks in the middle pane, polymorphic detail panel on the right; ▶ on a block starts/stops all its enabled tunnels
- Tunnel rows with five-state badges / ports / uptime / lazy ⋯ menu (retry, verify internet, deploy proxy, save as scenario…)
- Light & dark themes, three font sizes, **Chinese/English bilingual** (switchable in settings)
- Command builder: generates `ssh` / `autossh` commands for server↔server scenarios with per-flag explanations; named recipes
- Help page: three tunnel types illustrated, real-world scenario matching, FAQ
- All feedback via in-app toasts/dialogs — zero native popups

## Quick start

1. **Add a server**: Servers page → New; fill host / port / username (password is asked on first start, optionally remembered)
2. **Create a tunnel**: pick a server → New tunnel → choose a scenario preset (e.g. "VPN share", "reach intranet service") or blank custom
3. **Start**: hit ▶ on the server block to launch all enabled tunnels; closing the window minimizes to tray

## Build from source

Prerequisites: [Rust](https://rustup.rs/), Node.js ≥ 18, [Tauri v2 dependencies](https://v2.tauri.app/start/prerequisites/)

```bash
npm install
npm run tauri dev     # development
npm run tauri build   # installers (Windows: msi/nsis; macOS: app/dmg)
```

## Tests

```bash
cargo test -p proxy-tool-core                                          # all
cargo test -p proxy-tool-core --test e2e_tunnel -- --test-threads=1    # e2e (serial!)
```

E2E tests need a real SSH server: copy `core/.test-creds.local.example` to `core/.test-creds.local` (gitignored) and fill in host/password, or set `PROXYTOOL_TEST_SERVER / USER / PASS / PORT` env vars. **Real credentials never enter the repo.**

## Project layout

```
core/        tunnel engine (pure Rust): engine/ registry+state machine, transport/ std & compat modes,
             direct/ -L and -D, pool/ shared connections, secrets/ credential encryption, known_hosts/ TOFU
src-tauri/   Tauri GUI bridge: commands + event bridge + tray/autostart
src/         frontend (TypeScript, no framework): main/ui/theme/icons/i18n
docs/        design docs and refactoring notes
```
