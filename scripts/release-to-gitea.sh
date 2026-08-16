#!/usr/bin/env bash
# 同步 GitHub release 资产到 Gitea release。
# 背景: Gitea 无 runner, macOS dmg 只能在 GitHub Actions 云端构建 →
# 本脚本把 GitHub release 的全部资产下载后原样搬运到 Gitea 同名 release。
#
# 幂等: Gitea 上已有的 release / 同名附件自动跳过 —— 可反复跑,
# 例: 先传 Windows 包, mac CI 完成后再跑一次只补 dmg。
#
# 用法: scripts/release-to-gitea.sh <tag>            (如 v0.1.1)
# 认证: GITEA_TOKEN 环境变量, 或 scripts/.gitea-token.local 文件
#       (gitignored; Gitea → 头像 → Settings → Applications → Generate New Token)
# 可调环境变量: GH_BIN(默认 gh) / GH_REPO(默认 xiaofuce/proxyTool) /
#              GITEA_URL(默认 https://git.iomics.pro) / GITEA_REPO(默认 wangshangjian/proxyTool)
set -euo pipefail

TAG="${1:?用法: scripts/release-to-gitea.sh <tag>}"
GH_BIN="${GH_BIN:-gh}"
GH_REPO="${GH_REPO:-xiaofuce/proxyTool}"
GITEA_URL="${GITEA_URL:-https://git.iomics.pro}"
GITEA_REPO="${GITEA_REPO:-wangshangjian/proxyTool}"

TOKEN="${GITEA_TOKEN:-$(cat "$(dirname "$0")/.gitea-token.local" 2>/dev/null || true)}"
[ -n "$TOKEN" ] || {
    echo "缺 Gitea token: Gitea → 头像 → Settings → Applications → Generate New Token,"
    echo "把 token 存入 scripts/.gitea-token.local (已 gitignore) 或设 GITEA_TOKEN 环境变量"
    exit 1
}

# node 小助手: stdin JSON → 取字段 (jq 缺席, 用 node)
jget() { node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const j=JSON.parse(d);console.log(eval('j.'+process.argv[1])??'')}catch{console.log('')}})" "$1"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> 从 GitHub $GH_REPO 拉取 release $TAG (资产 + 说明)"
"$GH_BIN" release download "$TAG" --repo "$GH_REPO" --dir "$TMP" --clobber
RELEASE_NAME=$("$GH_BIN" release view "$TAG" --repo "$GH_REPO" --json name -q .name)
"$GH_BIN" release view "$TAG" --repo "$GH_REPO" --json body -q .body > "$TMP/.notes.md"

API="$GITEA_URL/api/v1/repos/$GITEA_REPO"
AUTH="Authorization: token $TOKEN"

echo "==> 查找/创建 Gitea release $TAG"
REL_JSON=$(curl -sf -H "$AUTH" "$API/releases/tags/$TAG" || true)
if [ -z "$REL_JSON" ] || [ "$(echo "$REL_JSON" | jget id)" = "" ]; then
    node -e "const fs=require('fs');fs.writeFileSync(process.argv[1],JSON.stringify({
        tag_name: process.argv[2],
        name: process.argv[3],
        body: fs.readFileSync(process.argv[4],'utf8'),
    }))" "$TMP/.payload.json" "$TAG" "$RELEASE_NAME" "$TMP/.notes.md"
    REL_JSON=$(curl -sf -H "$AUTH" -H "Content-Type: application/json" \
        -d @"$TMP/.payload.json" "$API/releases")
    echo "    已创建 release"
else
    echo "    release 已存在, 复用"
fi
REL_ID=$(echo "$REL_JSON" | jget id)
[ -n "$REL_ID" ] || { echo "拿不到 release id: $REL_JSON"; exit 1; }

# 已有附件名清单 (幂等跳过)
HAS=$(echo "$REL_JSON" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log((j.assets||[]).map(a=>a.name).join('\n'))})")

echo "==> 上传资产到 Gitea"
for f in "$TMP"/*; do
    base=$(basename "$f")
    case "$base" in .*) continue ;; esac
    if echo "$HAS" | grep -qxF "$base"; then
        echo "    跳过 (已存在): $base"
        continue
    fi
    curl -sf -H "$AUTH" -F "attachment=@$f" \
        "$API/releases/$REL_ID/assets?name=$base" > /dev/null
    echo "    已上传: $base"
done

echo "完成: $GITEA_URL/$GITEA_REPO/releases/tag/$TAG"
