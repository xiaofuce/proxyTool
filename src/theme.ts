// 外观偏好: 主题三态 (浅色 / 跟随系统 / 深色) + 字体大小三档 (小 / 标准 / 大)。
// 持久化 localStorage("pt-theme" / "pt-font"), 解析结果写 html[data-theme] /
// html[data-font] (styles.css 色板与 --fs 阶梯的选择器)。
// 防闪烁的初值解析在 index.html 内联脚本 (样式表加载前), 这里只负责切换与控件。
import { icon, type IconName } from "./icons";

export type ThemePref = "light" | "dark" | "system";
export type FontPref = "sm" | "md" | "lg";

const THEME_KEY = "pt-theme";
const FONT_KEY = "pt-font";
const MQ = "(prefers-color-scheme: dark)";

function resolve(pref: ThemePref): "light" | "dark" {
  return pref === "system"
    ? matchMedia(MQ).matches
      ? "dark"
      : "light"
    : pref;
}

/** 切换主题偏好: 解析 + 落 localStorage + 更新 html dataset */
export function setThemePref(pref: ThemePref): void {
  localStorage.setItem(THEME_KEY, pref);
  document.documentElement.dataset.themePref = pref;
  document.documentElement.dataset.theme = resolve(pref);
}

/** 切换字号档位 (--fs-* tokens 整体换档, 全 UI 即时缩放) */
export function setFontPref(pref: FontPref): void {
  localStorage.setItem(FONT_KEY, pref);
  document.documentElement.dataset.font = pref;
}

function syncSeg(seg: HTMLElement, attr: string, cur: string): void {
  for (const b of seg.querySelectorAll("button")) {
    const on = b.dataset[attr] === cur;
    b.classList.toggle("active", on);
    b.setAttribute("aria-pressed", String(on));
  }
}

/** 挂载设置页的两个分段控件 (主题 / 字体大小), 并监听系统主题变化实时跟随 */
export function initAppearance(): void {
  // 主题三态: 图标 + 文案
  const tseg = document.getElementById("set-theme");
  if (tseg) {
    const ITEMS: { pref: ThemePref; icon: IconName; label: string }[] = [
      { pref: "light", icon: "sun", label: "浅色" },
      { pref: "system", icon: "monitor", label: "跟随系统" },
      { pref: "dark", icon: "moon", label: "深色" },
    ];
    for (const { pref, icon: ic, label } of ITEMS) {
      const b = tseg.querySelector<HTMLButtonElement>(`[data-pref="${pref}"]`);
      if (!b) continue;
      b.innerHTML = `${icon(ic, 14)}<span class="btn-label"></span>`;
      b.querySelector(".btn-label")!.textContent = label;
      b.addEventListener("click", () => setThemePref(pref));
    }
    const cur = () =>
      (document.documentElement.dataset.themePref as ThemePref | undefined) ?? "system";
    tseg.addEventListener("click", () => syncSeg(tseg, "pref", cur()));
    syncSeg(tseg, "pref", cur());
  }

  // 字体三档: 纯文案
  const fseg = document.getElementById("set-font");
  if (fseg) {
    for (const b of fseg.querySelectorAll<HTMLButtonElement>("button")) {
      b.addEventListener("click", () => setFontPref((b.dataset.font ?? "md") as FontPref));
    }
    const cur = () => document.documentElement.dataset.font ?? "md";
    fseg.addEventListener("click", () => syncSeg(fseg, "font", cur()));
    syncSeg(fseg, "font", cur());
  }

  // system 态下系统主题切换 → 实时跟随 (无需 reload)
  matchMedia(MQ).addEventListener("change", () => {
    if (
      (document.documentElement.dataset.themePref as ThemePref | undefined) === "system"
    ) {
      document.documentElement.dataset.theme = resolve("system");
    }
  });
}
