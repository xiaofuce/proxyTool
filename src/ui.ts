// 函数式 UI 组件: toast / dialog / withLoading (U3)。
// 消费 styles.css 的设计 tokens, 不引框架; toast 栈与 modal 挂 body 级,
// 行内重绘 (renderTunnelRows 整表 innerHTML="") 不会销毁它们。
import { icon, type IconName } from "./icons";

// ---------- toast: 右下角栈, 同屏最多 4 条 ----------
export type ToastKind = "info" | "success" | "error";

const TOAST_ICONS: Record<ToastKind, IconName> = {
  info: "info",
  success: "check",
  error: "circle-alert",
};

let toastStack: HTMLDivElement | null = null;

/** kind=error 默认 5s (错误信息需要阅读时间), 其余 3s */
export function toast(msg: string, kind: ToastKind = "info", ms?: number): void {
  if (!toastStack || !toastStack.isConnected) {
    toastStack = document.createElement("div");
    toastStack.className = "toast-stack";
    document.body.append(toastStack);
  }
  const item = document.createElement("div");
  item.className = `toast ${kind}`;
  item.setAttribute("role", kind === "error" ? "alert" : "status");
  item.innerHTML = `${icon(TOAST_ICONS[kind], 15)}<span class="toast-msg"></span>`;
  const text = item.querySelector(".toast-msg")!;
  text.textContent = msg;
  toastStack.append(item);
  while (toastStack.children.length > 4) toastStack.firstElementChild!.remove();
  const life = ms ?? (kind === "error" ? 5000 : 3000);
  setTimeout(() => {
    item.classList.add("out");
    setTimeout(() => item.remove(), 200);
  }, life);
}

// ---------- dialog: 替代 confirm / prompt ----------
export interface DialogOptions {
  title: string;
  /** 纯文本 (textContent 渲染, 换行经 pre-line 生效) */
  body?: string;
  confirmText?: string;
  cancelText?: string;
  /** 确认钮红色 (删除/危险类操作) */
  danger?: boolean;
  /** 提供则带文本输入框 (替代 prompt) */
  input?: { value?: string; placeholder?: string };
}

/**
 * 无 input: true=确认 / false=取消 (Esc / 遮罩)。
 * 有 input: string=确认 (输入值, 可为空串) / null=取消。
 */
export function dialog(o: DialogOptions): Promise<boolean | string | null> {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";

    const modal = document.createElement("div");
    modal.className = "modal";
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-label", o.title);

    const title = document.createElement("div");
    title.className = "modal-title";
    if (o.danger) title.innerHTML = icon("triangle-alert", 16);
    const titleText = document.createElement("span");
    titleText.textContent = o.title;
    title.append(titleText);

    let input: HTMLInputElement | null = null;
    if (o.input) {
      input = document.createElement("input");
      input.type = "text";
      input.value = o.input.value ?? "";
      input.placeholder = o.input.placeholder ?? "";
    }

    const actions = document.createElement("div");
    actions.className = "modal-actions";
    const btnCancel = document.createElement("button");
    btnCancel.type = "button";
    btnCancel.textContent = o.cancelText ?? "取消";
    const btnConfirm = document.createElement("button");
    btnConfirm.type = "button";
    btnConfirm.className = o.danger ? "danger-primary" : "primary";
    btnConfirm.textContent = o.confirmText ?? "确定";
    actions.append(btnCancel, btnConfirm);

    modal.append(title);
    if (o.body) {
      const body = document.createElement("div");
      body.className = "modal-body";
      body.textContent = o.body;
      modal.append(body);
    }
    if (input) modal.append(input);
    modal.append(actions);
    overlay.append(modal);
    document.body.append(overlay);

    const cancelValue = o.input ? null : false;
    let settled = false;
    const done = (r: boolean | string | null) => {
      if (settled) return;
      settled = true;
      document.removeEventListener("keydown", onKey, true);
      overlay.remove();
      resolve(r);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        done(cancelValue);
      } else if (e.key === "Enter" && !(e.target as HTMLElement).closest("button")) {
        // 焦点在按钮上时 Enter 走原生 click (可能是取消钮)
        e.preventDefault();
        btnConfirm.click();
      } else if (e.key === "Tab") {
        const f = [input, btnCancel, btnConfirm].filter(Boolean) as HTMLElement[];
        const i = f.indexOf(document.activeElement as HTMLElement);
        e.preventDefault();
        f[(i + (e.shiftKey ? f.length - 1 : 1)) % f.length].focus();
      }
    };
    // mousedown (非 click): 框内选中文本拖出到遮罩不误关
    overlay.addEventListener("mousedown", (e) => {
      if (e.target === overlay) done(cancelValue);
    });
    document.addEventListener("keydown", onKey, true);
    btnCancel.addEventListener("click", () => done(cancelValue));
    btnConfirm.addEventListener("click", () => done(input ? input.value : true));

    (input ?? btnConfirm).focus();
    if (input) input.select();
  });
}

// ---------- menu: 行内 ⋯ 溢出菜单 (body 级单实例) ----------
export interface MenuItem {
  /** 分隔条条目可无文案 */
  label?: string;
  icon?: IconName;
  danger?: boolean;
  /** 三态: true 显勾 / false 显空位 / undefined 不显 (开关类条目) */
  checked?: boolean;
  disabled?: boolean;
  hidden?: boolean;
  separator?: boolean;
  /** 悬停提示 */
  title?: string;
  action?: () => void;
}

let menuEl: HTMLDivElement | null = null;
let menuCleanup: (() => void) | null = null;

/** 关闭当前菜单 (无菜单则空操作)。renderTunnelRows 重绘前调用, 防悬挂引用 */
export function closeMenus(): void {
  menuCleanup?.();
  menuCleanup = null;
}

/** 当前打开菜单的 tag (openMenu 第三参); 供「再点同一 ⋯ = 关闭」判定 */
export function menuTag(): string | null {
  return menuEl?.dataset.tag ?? null;
}

/**
 * 打开菜单。items 惰性求值 —— 打开瞬间才计算 hidden/disabled,
 * 天然解耦行重绘 (状态类条目按最新 state 出没)。
 * tag: 调用方标识 (隧道 id), 配 menuTag() 实现锚钮二次点击关闭。
 */
export function openMenu(anchor: HTMLElement, items: () => MenuItem[], tag?: string): void {
  closeMenus();
  const list = items().filter((it) => !it.hidden);
  if (!list.length) return;

  const menu = document.createElement("div");
  menu.className = "menu";
  menu.setAttribute("role", "menu");
  if (tag) menu.dataset.tag = tag;
  for (const it of list) {
    if (it.separator) {
      const sep = document.createElement("div");
      sep.className = "menu-sep";
      menu.append(sep);
      continue;
    }
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "menu-item" + (it.danger ? " danger" : "");
    btn.setAttribute("role", "menuitem");
    btn.disabled = it.disabled === true;
    if (it.title) btn.title = it.title;
    const hasCheck = it.checked !== undefined;
    btn.innerHTML =
      (it.icon ? icon(it.icon, 14) : "") +
      `<span class="menu-label"></span>` +
      (hasCheck ? `<span class="menu-check">${icon("check", 13)}</span>` : "");
    btn.querySelector<HTMLElement>(".menu-label")!.textContent = it.label ?? "";
    if (it.checked === false) btn.querySelector<HTMLElement>(".menu-check")!.classList.add("off");
    btn.addEventListener("click", () => {
      closeMenus();
      it.action?.();
    });
    menu.append(btn);
  }
  document.body.append(menu);
  menuEl = menu;

  // 定位: 右对齐锚点下方; 越出视口则翻转 (先渲染量尺寸再落位, 不闪)
  const r = anchor.getBoundingClientRect();
  menu.style.visibility = "hidden";
  const mw = menu.offsetWidth;
  const mh = menu.offsetHeight;
  let x = Math.min(Math.max(8, r.right - mw), innerWidth - 8 - mw);
  let y = r.bottom + 4;
  if (y + mh > innerHeight - 8) y = Math.max(8, r.top - mh - 4);
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  menu.style.visibility = "";

  const onDown = (e: PointerEvent) => {
    const tgt = e.target;
    if (tgt instanceof Node && (menu.contains(tgt) || anchor.contains(tgt))) return;
    // 锚点自身交由其 click 处理 (menuTag 命中 → 关闭, 实现 ⋯ 再点关闭)
    closeMenus();
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") closeMenus();
  };
  const onReflow = () => closeMenus();
  document.addEventListener("pointerdown", onDown, true);
  document.addEventListener("keydown", onKey, true);
  window.addEventListener("scroll", onReflow, true); // capture: 任意可滚容器
  window.addEventListener("resize", onReflow);

  menuCleanup = () => {
    document.removeEventListener("pointerdown", onDown, true);
    document.removeEventListener("keydown", onKey, true);
    window.removeEventListener("scroll", onReflow, true);
    window.removeEventListener("resize", onReflow);
    menu.remove();
    menuEl = null;
  };

  menu.querySelector<HTMLButtonElement>(".menu-item:not(:disabled)")?.focus();
}

// ---------- withLoading: 按钮 busy 态 (disabled + spinner + 文案) ----------
/**
 * 只改 .btn-label 的 textContent (图标 SVG 不丢); 无 .btn-label 的纯文本钮
 * 回退改整钮 textContent。fn 抛错也恢复原状后原样上抛。
 */
export async function withLoading<T>(
  btn: HTMLButtonElement | null | undefined,
  fn: () => Promise<T>,
  busyText?: string
): Promise<T> {
  if (!btn) return fn();
  const label = btn.querySelector(".btn-label");
  const prev = label ? label.textContent : btn.textContent;
  btn.disabled = true;
  btn.classList.add("btn-busy");
  if (busyText) {
    if (label) label.textContent = busyText;
    else btn.textContent = busyText;
  }
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.classList.remove("btn-busy");
    if (busyText) {
      if (label) label.textContent = prev;
      else btn.textContent = prev;
    }
  }
}
