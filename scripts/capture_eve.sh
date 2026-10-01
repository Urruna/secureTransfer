#!/usr/bin/env bash
# ============================================================================
#  SecureTransfer - Eve 窃听演示（抓包 + 明文检索）
#
#  用途：在 Bob 监听端口上抓包，然后跑一次 alice/bob，
#        检查网络上传的是密文，明文关键字不应出现在抓包结果里。
#
#  用法：
#      bash scripts/capture_eve.sh [端口] [明文关键字]
#      bash scripts/capture_eve.sh 9000 "Hello Bob"
#
#  需要 tcpdump（需要 sudo 权限）。
# ============================================================================
set -u

PORT="${1:-9000}"
KEYWORD="${2:-Hello Bob}"
CAPTURE="/tmp/eve_capture_${PORT}.pcap"
LOG="/tmp/eve_alice_${PORT}.log"
BUILD_DIR="$(cd "$(dirname "$0")/.." && pwd)/build"

echo "==================== Eve 窃听演示 ===================="
echo "端口      : ${PORT}"
echo "检索关键字: ${KEYWORD}"
echo "抓包文件  : ${CAPTURE}"
echo

echo "[1/4] 启动抓包（后台）..."
sudo rm -f "${CAPTURE}"
# -U：包到达即写盘，避免 tcpdump 缓冲区没刷新导致抓包文件是空的
sudo tcpdump -U -i lo -X "port ${PORT}" -w "${CAPTURE}" >/dev/null 2>&1 &
sleep 2

echo "[2/4] 启动 Bob ..."
(cd "${BUILD_DIR}" && ./bob "${PORT}" --quiet >/tmp/eve_bob_${PORT}.log 2>&1) &
BOB_PID=$!
sleep 1

echo "[3/4] 启动 Alice ..."
(cd "${BUILD_DIR}" && ./alice 127.0.0.1 "${PORT}" --quiet >"${LOG}" 2>&1)
wait "${BOB_PID}" 2>/dev/null

echo "[4/4] 停止抓包并分析 ..."
sleep 2
# 注意：后台进程是 sudo，直接 kill 那个 PID 只能杀掉 sudo 本身，
# tcpdump 会继续运行且缓冲区不落盘，所以按进程名结束它。
sudo pkill -INT -x tcpdump 2>/dev/null || true
sleep 2
sudo pkill -x tcpdump 2>/dev/null || true
sleep 1

if [ ! -f "${CAPTURE}" ]; then
    echo "[ERROR] 抓包失败：没有生成 ${CAPTURE}"
    exit 1
fi

COUNT="$(strings "${CAPTURE}" | grep -c "${KEYWORD}" || true)"
PLAIN_IN_LOG="$(grep -c "${KEYWORD}" "${LOG}" || true)"

echo
echo "-------------------- 结果 --------------------"
echo "抓包字节数                        : $(wc -c <"${CAPTURE}")"
echo "抓包中出现明文关键字的次数        : ${COUNT}   (期望 0)"
echo "Alice 终端日志中出现关键字的次数  : ${PLAIN_IN_LOG}   (应大于 0，说明确实发过这条消息)"
echo
echo "可以观察到（公开字段，密文与认证标签）："
strings "${CAPTURE}" | grep -c "ST" || true
echo
if [ "${COUNT}" -eq 0 ] && [ "${PLAIN_IN_LOG}" -gt 0 ]; then
    echo "[PASS] 窃听者只能看到密文，看不到明文。"
else
    echo "[FAIL] 请检查：明文是否泄漏，或 Alice 是否真的发送了该消息。"
    exit 1
fi
