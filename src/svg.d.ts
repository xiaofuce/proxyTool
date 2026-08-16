/** lucide-static 深路径 `?raw` 导入 (vite 原生支持, 返回 SVG 字符串) */
declare module "*.svg?raw" {
  const content: string;
  export default content;
}
