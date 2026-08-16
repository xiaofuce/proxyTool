// lucide-static 图标: 深路径 ?raw 导入 SVG 字符串, icon() 归一化为内联可染色的 16px 图标。
// 全部图标显式具名导入 (noUnusedLocals 约束); 新增图标时在 ICONS 补一条。
// 文件名以 node_modules/lucide-static/icons/ 实际为准 (注意 lucide 改名史: more-horizontal→ellipsis 等)。
import server from "lucide-static/icons/server.svg?raw";
import arrowRightLeft from "lucide-static/icons/arrow-right-left.svg?raw";
import settings from "lucide-static/icons/settings.svg?raw";
import play from "lucide-static/icons/play.svg?raw";
import square from "lucide-static/icons/square.svg?raw";
import chevronRight from "lucide-static/icons/chevron-right.svg?raw";
import arrowLeft from "lucide-static/icons/arrow-left.svg?raw";
import plus from "lucide-static/icons/plus.svg?raw";
import key from "lucide-static/icons/key.svg?raw";
import x from "lucide-static/icons/x.svg?raw";
import sun from "lucide-static/icons/sun.svg?raw";
import moon from "lucide-static/icons/moon.svg?raw";
import monitor from "lucide-static/icons/monitor.svg?raw";
import globe from "lucide-static/icons/globe.svg?raw";
import terminal from "lucide-static/icons/terminal.svg?raw";
import info from "lucide-static/icons/info.svg?raw";
import check from "lucide-static/icons/check.svg?raw";
import circleAlert from "lucide-static/icons/circle-alert.svg?raw";
import triangleAlert from "lucide-static/icons/triangle-alert.svg?raw";
import ellipsis from "lucide-static/icons/ellipsis.svg?raw";
import rotateCcw from "lucide-static/icons/rotate-ccw.svg?raw";
import shieldCheck from "lucide-static/icons/shield-check.svg?raw";
import bookmark from "lucide-static/icons/bookmark.svg?raw";
import power from "lucide-static/icons/power.svg?raw";
import trash2 from "lucide-static/icons/trash-2.svg?raw";
import copy from "lucide-static/icons/copy.svg?raw";
import eraser from "lucide-static/icons/eraser.svg?raw";
import waypoints from "lucide-static/icons/waypoints.svg?raw";

const ICONS = {
  server,
  "arrow-right-left": arrowRightLeft,
  settings,
  play,
  square,
  "chevron-right": chevronRight,
  "arrow-left": arrowLeft,
  plus,
  key,
  x,
  sun,
  moon,
  monitor,
  globe,
  terminal,
  info,
  check,
  "circle-alert": circleAlert,
  "triangle-alert": triangleAlert,
  ellipsis,
  "rotate-ccw": rotateCcw,
  "shield-check": shieldCheck,
  bookmark,
  power,
  "trash-2": trash2,
  copy,
  eraser,
  waypoints,
} as const;

export type IconName = keyof typeof ICONS;

/**
 * 生成内联 SVG 字符串 (currentColor 染色, 跟随文字色; 剥 license 注释,
 * 重设尺寸, 附 .ic class 供对齐/缩放统一控制)。
 */
export function icon(name: IconName, size = 16): string {
  return ICONS[name]
    .replace(/^<!--[\s\S]*?-->\s*/, "")
    .replace('class="', 'class="ic ')
    .replace('width="24"', `width="${size}"`)
    .replace('height="24"', `height="${size}"`);
}
