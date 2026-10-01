#!/usr/bin/env bash
# ============================================================================
#  把 securityTransfer 复制到 /home/securityTransfer 目录
#
#  用法：
#      bash scripts/deploy_to_home.sh              # 复制到 /home/securityTransfer
#      bash scripts/deploy_to_home.sh /tmp/demo    # 复制到指定目录
#
#  说明：
#      /home 通常需要管理员权限，脚本会在必要时使用 sudo。
#      复制完成后会把目录所有者改成当前用户，方便直接编译。
# ============================================================================

set -euo pipefail

source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_dir="${1:-/home/securityTransfer}"

echo "源目录  : ${source_dir}"
echo "目标目录: ${target_dir}"

if [ -e "${target_dir}" ]; then
    echo "目标目录已存在：${target_dir}"
    echo "将用当前源码覆盖其中的源码文件（build/ 目录与已有 keys.conf 会保留）。"
fi

if mkdir -p "${target_dir}" 2>/dev/null; then
    cp -r "${source_dir}/." "${target_dir}/"
else
    echo "需要管理员权限在 $(dirname "${target_dir}") 下创建目录，尝试使用 sudo ..."
    sudo mkdir -p "${target_dir}"
    sudo cp -r "${source_dir}/." "${target_dir}/"
    sudo chown -R "$(id -u):$(id -g)" "${target_dir}"
fi

echo "完成。接下来："
if [ ! -f "${target_dir}/configs/keys.conf" ] && [ -f "${target_dir}/configs/keys.conf.example" ]; then
    cp "${target_dir}/configs/keys.conf.example" "${target_dir}/configs/keys.conf"
    echo "（已根据模板生成 configs/keys.conf）"
fi
echo "    chmod 600 ${target_dir}/configs/keys.conf"
echo "    cd ${target_dir}"
echo "    mkdir -p build && cd build && cmake .. && cmake --build ."
