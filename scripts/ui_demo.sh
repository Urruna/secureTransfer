#!/usr/bin/env bash
# ============================================================================
#  SecureTransfer - 图形界面演示（含自动截图）
#
#  前置条件：
#      * 已安装 Qt5 开发包（sudo apt install -y qtbase5-dev）并编译出 build/st_ui
#      * 在虚拟机**桌面会话**里运行（脚本使用 DISPLAY=:0）
#
#  用法：
#      bash scripts/ui_demo.sh              # 两个场景都跑，并尝试截图
#      bash scripts/ui_demo.sh --no-shot    # 只跑演示，不截图
#
#  场景：
#      1) 图形界面作为服务端，命令行 Alice 驱动（消息 + 命令 + 1MB 文件 + 图像）
#      2) 图形界面作为客户端，自动发送（中文短消息 + 命令 + 1MB 文件 + 图像）
# ============================================================================
set -u

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
DATA_DIR="${PROJECT_DIR}/experiment_data"
OUT_DIR="${DATA_DIR}/received"
ACCESS_LOG="${DATA_DIR}/access_log.txt"
export DISPLAY="${DISPLAY:-:0}"

SHOT=1
for arg in "$@"; do
    [ "${arg}" = "--no-shot" ] && SHOT=0
done

if [ ! -x "${BUILD_DIR}/st_ui" ]; then
    echo "[ERROR] 找不到 ${BUILD_DIR}/st_ui，请先安装 Qt5 并编译："
    echo "        sudo apt install -y qtbase5-dev"
    echo "        cd ${BUILD_DIR} && cmake .. && cmake --build . -j4"
    exit 1
fi
mkdir -p "${OUT_DIR}"

take_shot() {
    local target="$1"
    if [ "${SHOT}" -eq 0 ]; then
        return 0
    fi
    command -v xwd >/dev/null 2>&1 || { echo "[WARN] 没有 xwd，跳过截图"; return 0; }
    local win
    win=$(xwininfo -root -tree 2>/dev/null | grep SecureTransfer | grep -v "Client Leader" \
          | grep -v "Selection Owner" | head -1 | awk '{print $1}')
    if [ -z "${win}" ]; then
        echo "[WARN] 没找到界面窗口，跳过截图"
        return 0
    fi
    xwd -id "${win}" -silent > "${target}" 2>/dev/null
    echo "[INFO] 已截图：${target}（窗口 ${win}）"
}

echo "==================== 场景 1：图形界面作为服务端 ===================="
pkill -f "st_ui --server" 2>/dev/null
sleep 1
nohup "${BUILD_DIR}/st_ui" --server --id bob --peer alice --port 9400 --auto \
    --out-dir "${OUT_DIR}" --access-log "${ACCESS_LOG}" >/tmp/st_ui_server.log 2>&1 &
sleep 3
(cd "${BUILD_DIR}" && ./alice 127.0.0.1 9400 --id alice --quiet --whoami --view-log \
    --file test_file_1MB.bin --image test_image_256x256.png)
echo "Alice 退出码=$?"
sleep 2
take_shot /tmp/st_ui_server.xwd
echo "--- 界面（服务端）日志节选 ---"
grep -E "Handshake|Transfer|AccessControl" /tmp/st_ui_server.log | tail -10
pkill -f "st_ui --server" 2>/dev/null
sleep 2

echo
echo "==================== 场景 2：图形界面作为客户端 ===================="
(cd "${BUILD_DIR}" && ./bob 9500 --peer alice --id bob --quiet \
    --out-dir "${OUT_DIR}" --access-log "${ACCESS_LOG}" >/tmp/st_ui_cli_bob.log 2>&1 &)
sleep 1
nohup "${BUILD_DIR}/st_ui" --client --auto --port 9500 --id alice --peer bob \
    --send-text "你好，Bob，这是从图形界面发出的安全消息。" --cmd WHOAMI \
    --send-file "${DATA_DIR}/test_file_1MB.bin" \
    --send-image "${DATA_DIR}/test_image_256x256.png" >/tmp/st_ui_client.log 2>&1 &
sleep 8
take_shot /tmp/st_ui_client.xwd
echo "--- 界面（客户端）日志节选 ---"
grep -E "Handshake|Transfer" /tmp/st_ui_client.log | tail -8
pkill -x bob 2>/dev/null
pkill -f "st_ui --client" 2>/dev/null
sleep 1

echo
echo "==================== 审计日志（共 $(wc -l < "${ACCESS_LOG}") 条）===================="
tail -8 "${ACCESS_LOG}"
echo
echo "截图文件：/tmp/st_ui_server.xwd、/tmp/st_ui_client.xwd"
echo "转成 PNG：在主机上用 python 脚本解析 xwd，或安装 imagemagick 后：xwd | convert xwd:- out.png"
