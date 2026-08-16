// 主题三态 (浅色 / 跟随系统 / 深色)。持久化 localStorage("pt-theme"),
// 解析结果写 html[data-theme] (styles.css 两套色板的选择器)。
// 防闪烁的初值解析在 index.html 内联脚本 (样式表加载前), 这里只负责切换与控件。
import { icon, type IconName } from "./icons";

export type ThemePref = "light" | "dark" | "system";

const STORAGE_KEY = "pt-theme";
const MQ = "(prefers-color-scheme: dark)";

function resolve(pref: ThemePref): "light" | "dark" {
  return pref === "system"
    ? matchMedia(MQ).matches
      ? "dark"
      : "light"
    : pref;
}

/** 切换偏好: 解析 + 落 localStorage + 更新 html dataset */
export function setThemePref(pref: ThemePref): void {
  localStorage.setItem(STORAGE_KEY, pref);
  document.documentElement.dataset.themePref = pref;
  document.documentElement.dataset.theme = resolve(pref);
}

/** 挂载侧栏底部三格分段控件 (图标由 JS 填充), 并监听系统主题变化实时跟随 */
export function initTheme(): void {
  const seg = document.getElementById("theme-toggle");
  if (!seg) return;

  const ITEMS: { pref: ThemePref; icon: IconName; title: string }[] = [
    { pref: "light", icon: "sun", title: "浅色" },
    { pref: "system", icon: "monitor", title: "跟随系统" },
    { pref: "dark", icon: "moon", title: "深色" },
  ];
  for (const { pref, icon: ic, title } of ITEMS) {
    const b = seg.querySelector<HTMLButtonElement>(`[data-pref="${pref}"]`);
    if (!b) continue;
    b.title = title;
    b.setAttribute("aria-label", title);
    b.innerHTML = icon(ic, 14);
    b.addEventListener("click", () => setThemePref(pref));
  }

  const sync = () => {
    const cur =
      (document.documentElement.dataset.themePref as ThemePref | undefined) ??
      "system";
    for (const b of seg.querySelectorAll("button")) {
      const on = b.dataset.pref === cur;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", String(on));
    }
  };
  // 点击冒泡到 seg 时再同步 (按钮监听先执行, dataset 已更新)
  seg.addEventListener("click", sync);
  sync();

  // system 态下系统主题切换 → 实时跟随 (无需 reload)
  matchMedia(MQ).addEventListener("change", () => {
    if (
      (document.documentElement.dataset.themePref as ThemePref | undefined) ===
      "system"
    ) {
      document.documentElement.dataset.theme = resolve("system");
    }
  });
}
