import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type Kind = "remote" | "local" | "dynamic";

interface Profile {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
}

// ---------- 工具 ----------
function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function log(kind: Kind, msg: string) {
  const area = el<HTMLPreElement>(`log-${kind}`);
  const ts = new Date().toLocaleTimeString();
  area.textContent += `[${ts}] ${msg}\n`;
  area.scrollTop = area.scrollHeight;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!;
  });
}

// ---------- 页面路由 ----------
const navItems = document.querySelectorAll<HTMLButtonElement>(".nav-item");
const pages = document.querySelectorAll<HTMLElement>(".page");

function showPage(name: string) {
  navItems.forEach((b) => b.classList.toggle("active", b.dataset.page === name));
  pages.forEach((p) => p.classList.toggle("active", p.dataset.page === name));
}
navItems.forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page!)));

// ---------- 各隧道页状态 ----------
const states: Record<Kind, { connected: boolean }> = {
  remote: { connected: false },
  local: { connected: false },
  dynamic: { connected: false },
};

const STATUS_TEXT: Record<string, string> = {
  connecting: "连接中...",
  connected: "已连接",
  disconnected: "已断开",
  error: "错误",
};

function setStatus(kind: Kind, state: string, message?: string) {
  const badge = el<HTMLDivElement>(`status-${kind}`);
  badge.className = `badge ${state}`;
  badge.textContent = STATUS_TEXT[state] ?? state;

  const dot = document.getElementById(`dot-${kind}`);
  if (dot) dot.className = `nav-dot ${state}`;

  const connected = state === "connected";
  states[kind].connected = connected;
  el<HTMLButtonElement>(`connect-${kind}`).disabled = connected || state === "connecting";
  el<HTMLButtonElement>(`disconnect-${kind}`).disabled = !connected;
  if (kind === "remote") {
    el<HTMLButtonElement>("verify-remote").disabled = !connected;
    el<HTMLButtonElement>("deploy-remote").disabled = !connected;
  }
  if (message) log(kind, `❌ ${message}`);
}

// ---------- 后端事件 ----------
listen("tunnel-status", (e) => {
  const p = e.payload as { kind: Kind; state: string; message?: string };
  setStatus(p.kind, p.state, p.message);
});

listen("tunnel-log", (e) => {
  const p = e.payload as { kind: Kind; msg: string };
  log(p.kind, p.msg);
});

// ---------- 隧道页通用接线 ----------
const DISCONNECT_CMDS: Record<Kind, string> = {
  remote: "disconnect_tunnel",
  local: "disconnect_local",
  dynamic: "disconnect_dynamic",
};

function wireTunnelPage(kind: Kind, connectCmd: string, collect: () => Record<string, unknown>) {
  el<HTMLFormElement>(`form-${kind}`).addEventListener("submit", async (e) => {
    e.preventDefault();
    if (states[kind].connected) return;
    setStatus(kind, "connecting");
    log(kind, "发起连接...");
    try {
      await invoke(connectCmd, collect());
      // 连接流程已在后台进行, 等待 tunnel-status 事件
    } catch (err) {
      log(kind, `❌ ${err}`);
      setStatus(kind, "idle");
    }
  });

  el<HTMLButtonElement>(`disconnect-${kind}`).addEventListener("click", async () => {
    try {
      await invoke(DISCONNECT_CMDS[kind]);
      log(kind, "请求断开...");
    } catch (err) {
      log(kind, `❌ ${err}`);
    }
  });
}

// ---------- 反向隧道页 ----------
wireTunnelPage("remote", "connect_tunnel", () => ({
  serverHost: el<HTMLInputElement>("server-host-remote").value.trim(),
  serverPort: Number(el<HTMLInputElement>("server-port-remote").value),
  username: el<HTMLInputElement>("username-remote").value.trim(),
  password: el<HTMLInputElement>("password-remote").value,
  remotePort: Number(el<HTMLInputElement>("remote-port").value),
  localProxyPort: Number(el<HTMLInputElement>("local-proxy-port").value),
}));

// 探测本机 SOCKS 代理端口
el<HTMLButtonElement>("probe-btn").addEventListener("click", async () => {
  const btn = el<HTMLButtonElement>("probe-btn");
  const result = el<HTMLDivElement>("probe-result");
  btn.disabled = true;
  result.textContent = "探测中...";
  try {
    const results = await invoke<Array<{ port: number; socks5_confirmed: boolean }>>(
      "probe_local_proxy"
    );
    if (results.length === 0) {
      result.textContent = "未发现本地 SOCKS 代理，请确认 VPN 已开启";
    } else {
      const summary = results
        .map((r) => `${r.port}${r.socks5_confirmed ? "(SOCKS5✓)" : ""}`)
        .join(", ");
      result.textContent = `发现端口: ${summary}`;
      const socks = results.find((r) => r.socks5_confirmed);
      if (socks) el<HTMLInputElement>("local-proxy-port").value = String(socks.port);
    }
  } catch (e) {
    result.textContent = `探测失败: ${e}`;
  } finally {
    btn.disabled = false;
  }
});

// 验证外网 (需已连接): 服务器上经隧道 curl google
el<HTMLButtonElement>("verify-remote").addEventListener("click", async () => {
  const btn = el<HTMLButtonElement>("verify-remote");
  btn.disabled = true;
  btn.textContent = "验证中...";
  try {
    const out = await invoke<string>("verify_remote_tunnel", {
      serverHost: el<HTMLInputElement>("server-host-remote").value.trim(),
      serverPort: Number(el<HTMLInputElement>("server-port-remote").value),
      username: el<HTMLInputElement>("username-remote").value.trim(),
      password: el<HTMLInputElement>("password-remote").value,
      remotePort: Number(el<HTMLInputElement>("remote-port").value),
    });
    log("remote", `\n${out}`);
  } catch (err) {
    log("remote", `❌ 验证失败: ${err}`);
  } finally {
    btn.disabled = !states.remote.connected;
    btn.textContent = "验证外网";
  }
});

// 部署 proxy wrapper (需已连接)
el<HTMLButtonElement>("deploy-remote").addEventListener("click", async () => {
  const btn = el<HTMLButtonElement>("deploy-remote");
  btn.disabled = true;
  btn.textContent = "部署中...";
  try {
    const out = await invoke<string>("deploy_wrapper", {
      serverHost: el<HTMLInputElement>("server-host-remote").value.trim(),
      serverPort: Number(el<HTMLInputElement>("server-port-remote").value),
      username: el<HTMLInputElement>("username-remote").value.trim(),
      password: el<HTMLInputElement>("password-remote").value,
      remotePort: Number(el<HTMLInputElement>("remote-port").value),
    });
    log("remote", `\n${out}`);
  } catch (err) {
    log("remote", `❌ 部署失败: ${err}`);
  } finally {
    btn.disabled = !states.remote.connected;
    btn.textContent = "部署 proxy";
  }
});

// ---------- 本地转发页 ----------
wireTunnelPage("local", "connect_local", () => ({
  serverHost: el<HTMLInputElement>("server-host-local").value.trim(),
  serverPort: Number(el<HTMLInputElement>("server-port-local").value),
  username: el<HTMLInputElement>("username-local").value.trim(),
  password: el<HTMLInputElement>("password-local").value,
  listenPort: Number(el<HTMLInputElement>("listen-port-local").value),
  targetHost: el<HTMLInputElement>("target-host-local").value.trim(),
  targetPort: Number(el<HTMLInputElement>("target-port-local").value),
}));

// ---------- 动态隧道页 ----------
wireTunnelPage("dynamic", "connect_dynamic", () => ({
  serverHost: el<HTMLInputElement>("server-host-dynamic").value.trim(),
  serverPort: Number(el<HTMLInputElement>("server-port-dynamic").value),
  username: el<HTMLInputElement>("username-dynamic").value.trim(),
  password: el<HTMLInputElement>("password-dynamic").value,
  listenPort: Number(el<HTMLInputElement>("listen-port-dynamic").value),
}));

// ---------- 服务器配置档案 ----------
async function refreshProfiles() {
  const list = await invoke<Profile[]>("list_profiles");
  const container = el<HTMLDivElement>("profile-list");
  container.innerHTML = "";
  if (list.length === 0) {
    container.innerHTML = '<div class="hint">还没有保存的服务器，用上方表单添加</div>';
    return;
  }
  list.forEach((p) => {
    const row = document.createElement("div");
    row.className = "profile-row";

    const info = document.createElement("div");
    info.className = "profile-info";
    info.innerHTML = `<strong>${escapeHtml(p.name)}</strong><span>${escapeHtml(p.host)}:${p.port} (${escapeHtml(p.username)})</span>`;

    const fillBtn = document.createElement("button");
    fillBtn.type = "button";
    fillBtn.textContent = "填入";
    fillBtn.title = "填入各隧道页面的服务器表单";
    fillBtn.addEventListener("click", () => fillServerFields(p));

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.textContent = "删除";
    delBtn.className = "danger";
    delBtn.addEventListener("click", async () => {
      try {
        await invoke("delete_profile", { id: p.id });
        await refreshProfiles();
      } catch (err) {
        log("remote", `❌ 删除失败: ${err}`);
      }
    });

    row.append(info, fillBtn, delBtn);
    container.append(row);
  });
}

function fillServerFields(p: Profile) {
  (["remote", "local", "dynamic"] as Kind[]).forEach((kind) => {
    el<HTMLInputElement>(`server-host-${kind}`).value = p.host;
    el<HTMLInputElement>(`server-port-${kind}`).value = String(p.port);
    el<HTMLInputElement>(`username-${kind}`).value = p.username;
  });
  showPage("remote");
  log("remote", `已填入服务器「${p.name}」 (${p.host}:${p.port})，密码请手动输入`);
}

el<HTMLFormElement>("profile-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = el<HTMLInputElement>("profile-name").value.trim();
  const host = el<HTMLInputElement>("profile-host").value.trim();
  const port = Number(el<HTMLInputElement>("profile-port").value);
  const username = el<HTMLInputElement>("profile-user").value.trim();
  if (!name || !host || !username) {
    alert("请填写名称、地址和用户名");
    return;
  }
  try {
    const id = el<HTMLInputElement>("profile-id").value || crypto.randomUUID();
    await invoke("save_profile", { profile: { id, name, host, port, username } });
    clearProfileForm();
    await refreshProfiles();
  } catch (err) {
    alert(`保存失败: ${err}`);
  }
});

function clearProfileForm() {
  el<HTMLInputElement>("profile-id").value = "";
  el<HTMLInputElement>("profile-name").value = "";
  el<HTMLInputElement>("profile-host").value = "";
  el<HTMLInputElement>("profile-port").value = "22";
  el<HTMLInputElement>("profile-user").value = "";
}

el<HTMLButtonElement>("profile-clear").addEventListener("click", clearProfileForm);

// 初始化
refreshProfiles().catch((e) => log("remote", `❌ 加载服务器列表失败: ${e}`));
