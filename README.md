# proxyTool

一个小工具，一键建立「本地电脑 ⇄ 远程服务器」的 SSH 隧道。所有操作在本地 PC 完成，只需远程服务器账密（密码仅存内存，**不落盘**）。

## 功能模块

| 模块 | 等价命令 | 用途 |
|------|----------|------|
| **反向隧道** | `ssh -R` | 远程服务器借用本机 VPN 访问外网（本机 SOCKS 端口 → 服务器监听端口）。含自动探测 VPN 端口、内置 SOCKS 兜底、云主机安全组件兼容模式 |
| **本地转发** | `ssh -L` | 本机访问远程服务器上的服务（如远程 MySQL / Web） |
| **动态隧道** | `ssh -D` | 本机 SOCKS5 代理，经服务器访问其内网任意主机（DNS 服务器侧解析） |
| **服务器** | — | 保存常用服务器配置（名称/地址/端口/用户名，不含密码），一键填入各隧道表单 |

反向隧道页还提供：
- **验证外网**：在服务器上对比直连 vs 经隧道访问 google，验证端到端链路
- **部署 proxy**：把 `proxy` 命令部署到服务器（`proxy curl ...` 即走隧道出网）

## 技术栈

- GUI: **Tauri v2**（WebView 前端 + Rust 内核）
- SSH/隧道: **russh**（纯 Rust；`tcpip_forward` / `channel_open_direct_tcpip` / 会话通道）
- 运行时: tokio（经 `tauri::async_runtime::spawn`）

## 开发

```bash
npm install
npm run tauri dev      # 开发模式
npm run tauri build    # 打包
cargo test --test e2e_tunnel -- --nocapture   # 反向隧道端到端验收 (需服务器+VPN)
```

设计/调研结论见 docs/设计文档-调研结论.md；后续构思见 最新构思.md。
