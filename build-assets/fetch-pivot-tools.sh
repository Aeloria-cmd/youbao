#!/usr/bin/env bash
# fetch-pivot-tools.sh —— 构建镜像前在宿主机运行一次：
# 把内网横向/隧道工具（chisel、socat 静态二进制）下载到 build-assets/pivot/，
# Dockerfile 会把它们 COPY 进 /opt/pivot/。
#
# 用法: bash build-assets/fetch-pivot-tools.sh [amd64|arm64]   (默认 amd64)
set -uo pipefail

ARCH="${1:-amd64}"   # 镜像目标架构;hosted 镜像为 linux/amd64
OUT="$(cd "$(dirname "$0")" && pwd)/pivot"
mkdir -p "$OUT"

gh_latest_asset() {
  # $1=repo  $2=asset 名匹配正则 → 输出下载 URL
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" \
    | grep -oE '"browser_download_url": *"[^"]+"' \
    | sed -E 's/.*"(https:[^"]+)".*/\1/' \
    | grep -E "$2" \
    | head -1
}

echo "==> chisel (jpillora/chisel, linux/${ARCH})"
CHISEL_URL="$(gh_latest_asset 'jpillora/chisel' "chisel_.*linux_${ARCH}\\.gz$")"
if [ -n "$CHISEL_URL" ]; then
  curl -fsSL "$CHISEL_URL" -o "$OUT/chisel.gz" && gunzip -f "$OUT/chisel.gz" && chmod +x "$OUT/chisel"
  echo "    ok: $OUT/chisel"
else
  echo "    WARN: 未找到 chisel 资产,跳过(可手工下载放入 $OUT)"
fi

echo "==> socat 静态二进制 (ernw/static-toolbox, x86_64)"
if [ "$ARCH" = "amd64" ]; then
  SOCAT_URL="$(gh_latest_asset 'ernw/static-toolbox' 'socat.*(x86_64|amd64|linux64|linux-amd64)')"
  if [ -n "$SOCAT_URL" ]; then
    curl -fsSL "$SOCAT_URL" -o "$OUT/socat" && chmod +x "$OUT/socat"
    echo "    ok: $OUT/socat"
  else
    echo "    WARN: 未找到 socat 资产,跳过(可手工下载放入 $OUT)"
  fi
else
  echo "    arm64 跳过 socat(static-toolbox 仅 x86_64)"
fi

echo "完成。目录内容:"; ls -la "$OUT"
