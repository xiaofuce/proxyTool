#!/usr/bin/env bash
# 双远同步: 一份代码, 两条 ref, 不维护第二份拷贝。
#
#   main   全量历史      -> Gitea   (git push origin main)
#   public 过滤后的历史   -> GitHub  (本脚本, 强推 public:main)
#
# GitHub 排除路径见下方 EXCLUDES (CLAUDE.md / docs / 最新构思.md)。
# 过滤是确定性的: main 历史不变则 public 各提交 hash 稳定, 平时增量推送;
# main 重写历史后 public 整体换 hash, force push 覆盖即可。
#
# 用法:
#   scripts/sync-github.sh                 # 重建 public 并强推 github/main
#   scripts/sync-github.sh github --no-push # 只重建不推送 (校验用)
set -euo pipefail

EXCLUDES=(CLAUDE.md docs 最新构思.md)
REMOTE="${1:-github}"
NOPUSH="${2:-}"
SRC=main
DST=public

if [ "$NOPUSH" != "--no-push" ]; then
    git rev-parse --verify "$REMOTE" >/dev/null 2>&1 \
        || { echo "缺少远程 '$REMOTE': 先 git remote add $REMOTE <url>"; exit 1; }
fi

echo "==> 重建 $DST (源 $SRC, 排除: ${EXCLUDES[*]})"
git branch -f "$DST" "$SRC"
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch \
    --index-filter "git rm -r --cached --ignore-unmatch ${EXCLUDES[*]}" \
    --prune-empty "$DST" >/dev/null
git for-each-ref --format='%(refname)' refs/original/ \
    | while read -r r; do git update-ref -d "$r"; done

echo "==> 校验: $DST 全历史不含排除路径"
BAD=$(git rev-list "$DST" | while read -r c; do
    git -c core.quotepath=false ls-tree -r --name-only "$c"
done | sort -u | grep -E '^(CLAUDE\.md|docs/|最新构思\.md)$' || true)
[ -z "$BAD" ] || { echo "校验失败, 仍存在: $BAD"; exit 1; }

echo "==> 校验: $DST 树 = $SRC 树减排除路径"
DIFF=$(comm -3 \
    <(git -c core.quotepath=false ls-tree -r --name-only "$SRC" | sort) \
    <(git -c core.quotepath=false ls-tree -r --name-only "$DST" | sort))
EXPECTED=$(git -c core.quotepath=false ls-tree -r --name-only "$SRC" | grep -E '^(CLAUDE\.md|docs/|最新构思\.md)$' | sort || true)
[ "$DIFF" = "$EXPECTED" ] || { echo "树差异异常: $DIFF"; exit 1; }

if [ "$NOPUSH" = "--no-push" ]; then
    echo "完成 (--no-push): $DST = $(git rev-parse --short "$DST"), $(git rev-list --count "$DST") 提交"
else
    git push -f "$REMOTE" "$DST:main"
    echo "完成: $REMOTE/main = $(git rev-parse --short "$DST"), $(git rev-list --count "$DST") 提交"
fi
