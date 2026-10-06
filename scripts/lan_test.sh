#!/usr/bin/env bash
# ============================================================================
#  SecureTransfer - 局域网 / 双机测试
#
#  对应课程要求 6：Alice 与 Bob 之间的信息交互必须经过网络传输。
#  本脚本提供两种用法：
#
#  (A) 单机模拟两台主机（默认，适合只有一台虚拟机时使用）
#      bash scripts/lan_test.sh --netns
#
#      做法：用 Linux 网络命名空间造出"两台独立主机"，中间接一台虚拟交换机：
#
#           主机 Alice（10.10.0.1/24） ── veth ──┐
#                                                ├── stbr0（虚拟交换机 / 局域网）
#           主机 Bob  （10.10.0.2/24） ── veth ──┘
#
#      两侧有各自独立的网卡、IP、路由表与 ARP 表，数据包真的经过以太网链路
#      （脚本会在交换机上抓包作为证据）。
#
#  (B) 真正的两台机器（两台电脑 / 两台虚拟机，处于同一局域网）
#      在 Bob 所在机器上：   bash scripts/lan_test.sh --server 9000
#      在 Alice 所在机器上： bash scripts/lan_test.sh --client 192.168.x.x 9000
#      两台机器的 configs/keys.conf 必须是同一把 K_master。
#
#  其它参数：
#      --port <端口>    默认 9000
#      --keep           测试结束后保留命名空间与抓包文件（便于手工观察）
#
#  非交互环境（例如通过脚本远程执行）可用环境变量传入 sudo 密码：
#      ST_SUDO_PW=xxxx bash scripts/lan_test.sh --netns
# ============================================================================
set -u

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"

PORT=9000
MODE=""
PEER_HOST=""
KEEP=0

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
sudo_run() {
    if [ -n "${ST_SUDO_PW:-}" ]; then
        printf '%s\n' "${ST_SUDO_PW}" | sudo -S "$@" 2>>"${SUDO_ERR_LOG}"
    else
        sudo "$@"
    fi
}

need_root() {
    if [ "$(id -u)" -eq 0 ]; then
        return 0
    fi
    if [ -n "${ST_SUDO_PW:-}" ]; then
        return 0
    fi
    if ! sudo -n true 2>/dev/null; then
        echo "[ERROR] 该模式需要 root 权限，请用 sudo 运行，或设置 ST_SUDO_PW"
        exit 1
    fi
}

check_binaries() {
    for exe in alice bob; do
        if [ ! -x "${BUILD_DIR}/${exe}" ]; then
            echo "[ERROR] 找不到 ${BUILD_DIR}/${exe}，请先编译：" 
            echo "        cd ${PROJECT_DIR}/build && cmake .. && cmake --build . -j4"
            exit 1
        fi
    done
    if [ ! -f "${PROJECT_DIR}/configs/keys.conf" ]; then
        echo "[ERROR] 缺少 configs/keys.conf（可由 keys.conf.example 复制）"
        exit 1
    fi
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --netns) MODE="netns" ;;
            --server) MODE="server"; shift; PORT="${1:-9000}" ;;
            --client) MODE="client"; shift; PEER_HOST="${1:-}"; shift; PORT="${1:-9000}" ;;
            --port) shift; PORT="${1:-9000}" ;;
            --keep) KEEP=1 ;;
            --help|-h)
                sed -n '2,30p' "$0"
                exit 0
                ;;
            *) echo "[ERROR] 未知参数: $1"; exit 1 ;;
        esac
        shift
    done
    if [ -z "${MODE}" ]; then
        MODE="netns"
    fi
}

# ---------------------------------------------------------------------------
# 模式 B：真机双机（本机只运行其中一侧）
# ---------------------------------------------------------------------------
run_server() {
    check_binaries
    echo "==================== Bob（服务端）===================="
    echo "监听端口 : ${PORT}"
    echo "本机地址 : $(hostname -I 2>/dev/null)"
    echo "对端请执行: bash scripts/lan_test.sh --client <本机IP> ${PORT}"
    echo "====================================================="
    cd "${BUILD_DIR}" || exit 1
    exec ./bob "${PORT}"
}

run_client() {
    check_binaries
    if [ -z "${PEER_HOST}" ]; then
        echo "[ERROR] --client 需要给出服务端 IP，例如：--client 192.168.1.20 9000"
        exit 1
    fi
    echo "==================== Alice（客户端）===================="
    echo "目标     : ${PEER_HOST}:${PORT}"
    echo "本机地址 : $(hostname -I 2>/dev/null)"
    echo "======================================================="
    cd "${BUILD_DIR}" || exit 1
    exec ./alice "${PEER_HOST}" "${PORT}"
}

# ---------------------------------------------------------------------------
# 模式 A：网络命名空间模拟两台主机（同一台机器上）
# ---------------------------------------------------------------------------
NS_ALICE="st-alice"
NS_BOB="st-bob"
LINK_A="stva"
LINK_B="stvb"
IP_ALICE="10.10.0.1"
IP_BOB="10.10.0.2"
PCAP="/tmp/st_lan_capture.pcap"
SUDO_ERR_LOG="/tmp/st_lan_sudo_err.log"

cleanup_netns() {
    sudo_run ip netns del "${NS_ALICE}" >/dev/null 2>&1 || true
    sudo_run ip netns del "${NS_BOB}" >/dev/null 2>&1 || true
    sudo_run ip link del "${LINK_A}" >/dev/null 2>&1 || true
    sudo_run ip link del "${LINK_B}" >/dev/null 2>&1 || true
}

run_netns() {
    need_root
    check_binaries
    : >"${SUDO_ERR_LOG}"

    echo "==================== 局域网双机测试（两台独立主机）===================="
    echo "主机 Alice : 网络命名空间 ${NS_ALICE}，网卡 ${LINK_A}，IP ${IP_ALICE}/24"
    echo "主机 Bob   : 网络命名空间 ${NS_BOB}，网卡 ${LINK_B}，IP ${IP_BOB}/24"
    echo "链路       : 一条虚拟以太网链路（等价于两台机器用网线相连）"
    echo "端口       : ${PORT}"
    echo "说明       : 两个命名空间各有独立的网卡 / IP / 路由表 / ARP 表，"
    echo "             报文真的经过以太网链路，可以在网卡上抓到。"
    echo "====================================================================="

    echo
    echo "[1/6] 清理可能存在的旧环境 ..."
    cleanup_netns

    echo "[2/6] 创建两台主机之间的以太网链路并配置 IP ..."
    sudo_run ip netns add "${NS_ALICE}"
    sudo_run ip netns add "${NS_BOB}"
    sudo_run ip link add "${LINK_A}" type veth peer name "${LINK_B}"
    sudo_run ip link set "${LINK_A}" netns "${NS_ALICE}"
    sudo_run ip link set "${LINK_B}" netns "${NS_BOB}"
    sudo_run ip netns exec "${NS_ALICE}" ip link set lo up
    sudo_run ip netns exec "${NS_BOB}" ip link set lo up
    sudo_run ip netns exec "${NS_ALICE}" ip link set "${LINK_A}" up
    sudo_run ip netns exec "${NS_ALICE}" ip addr add "${IP_ALICE}/24" dev "${LINK_A}"
    sudo_run ip netns exec "${NS_BOB}" ip link set "${LINK_B}" up
    sudo_run ip netns exec "${NS_BOB}" ip addr add "${IP_BOB}/24" dev "${LINK_B}"

    echo "[3/6] 验证两台主机之间的网络连通性（ping）..."
    if sudo_run ip netns exec "${NS_ALICE}" ping -c 2 -W 2 "${IP_BOB}" \
        >/tmp/st_lan_ping.log 2>&1; then
        echo "      Alice -> Bob 可达 ✅"
    else
        echo "      [WARN] ping 不通，详见 /tmp/st_lan_ping.log"
    fi

    echo "[4/6] 在 Alice 的网卡上抓包（证明数据确实走网络）..."
    sudo_run rm -f "${PCAP}"
    sudo_run ip netns exec "${NS_ALICE}" tcpdump -U -i "${LINK_A}" -w "${PCAP}" \
        >/tmp/st_lan_tcpdump.log 2>&1 &
    sleep 2

    echo "[5/6] 运行 Alice / Bob（安全握手 + 4 条加密消息 + CLOSE）..."
    # 用 timeout 防止对端未启动时无限阻塞（Bob 的 accept() 会一直等）
sudo_run timeout 60 ip netns exec "${NS_BOB}" "${BUILD_DIR}/bob" "${PORT}" --once --quiet \
        >/tmp/st_lan_bob.log 2>&1 &
    BOB_PID=$!
    sleep 1
    sudo_run timeout 60 ip netns exec "${NS_ALICE}" "${BUILD_DIR}/alice" "${IP_BOB}" "${PORT}" \
        --quiet >/tmp/st_lan_alice.log 2>&1
    ALICE_RC=$?
    wait "${BOB_PID}" 2>/dev/null
    BOB_RC=$?
    sleep 2

    echo "[6/6] 停止抓包并汇总结果 ..."
    sudo_run pkill -INT -x tcpdump >/dev/null 2>&1 || true
    sleep 2
    sudo_run pkill -x tcpdump >/dev/null 2>&1 || true
    sleep 1

    echo
    echo "------------------------- 结果 -------------------------"
    echo "Alice 退出码 : ${ALICE_RC}"
    echo "Bob   退出码 : ${BOB_RC}"
    echo
    echo "【两台主机的网卡与 IP（各自独立的网络栈）】"
    echo -n "  Alice: "
    sudo_run ip netns exec "${NS_ALICE}" ip -4 -br addr show "${LINK_A}" 2>/dev/null
    echo -n "  Bob  : "
    sudo_run ip netns exec "${NS_BOB}" ip -4 -br addr show "${LINK_B}" 2>/dev/null
    echo
    echo "【Alice 侧的邻居表（真实 ARP 记录，说明确实在同一局域网）】"
    sudo_run ip netns exec "${NS_ALICE}" ip neigh show 2>/dev/null
    echo
    echo "【链路上的抓包统计】"
    if [ -f "${PCAP}" ] && [ -s "${PCAP}" ]; then
        echo "  抓包文件大小   : $(stat -c%s "${PCAP}") 字节"
        echo "  数据包总数     : $(sudo_run tcpdump -r "${PCAP}" -nn 2>/dev/null | wc -l)"
        echo "  TCP SYN 包数量 : $(sudo_run tcpdump -r "${PCAP}" -nn 2>/dev/null | grep -c 'Flags \[S' || true)"
        echo "  明文泄露检查   : $(strings "${PCAP}" | grep -c 'Hello Bob' || true) 次（期望 0）"
        echo
        echo "【抓包中的前几行：可见 ${IP_ALICE} 与 ${IP_BOB} 之间的真实 TCP 握手】"
        sudo_run tcpdump -r "${PCAP}" -nn 2>/dev/null | head -8
    else
        echo "  [WARN] 没有抓到数据包（详见 /tmp/st_lan_tcpdump.log）"
    fi
    echo
    echo "【Bob 侧输出（节选）】"
    grep -E "完整性算法|安全会话已建立|第 1 条消息|解密明文|统计:" /tmp/st_lan_bob.log 2>/dev/null \
        || tail -5 /tmp/st_lan_bob.log 2>/dev/null
    echo
    echo "【Alice 侧输出（节选）】"
    grep -E "完整性算法|安全会话已建立|对端回复|统计:|测试消息全部安全传输成功" \
        /tmp/st_lan_alice.log 2>/dev/null | head -12 \
        || tail -5 /tmp/st_lan_alice.log 2>/dev/null
    echo

    if [ "${ALICE_RC}" -eq 0 ] && [ "${BOB_RC}" -eq 0 ]; then
        echo "[PASS] 两台独立主机之间完成了完整的安全通信（数据经过以太网链路）"
        PASSED=0
    else
        echo "[FAIL] 通信失败，请检查上面的日志"
        echo "       （sudo 相关报错见 ${SUDO_ERR_LOG}）"
        PASSED=1
    fi

    if [ "${KEEP}" -eq 1 ]; then
        echo
        echo "[INFO] 已保留两台主机与抓包文件（--keep）："
        echo "       sudo ip netns exec ${NS_BOB} bash     # 进入 Bob 主机"
        echo "       sudo ip netns exec ${NS_ALICE} bash   # 进入 Alice 主机"
        echo "       sudo tcpdump -r ${PCAP} -nn           # 查看抓包"
        echo "       清理： sudo ip netns del ${NS_ALICE}; sudo ip netns del ${NS_BOB}"
    else
        echo
        echo "[INFO] 正在清理两台虚拟主机 ..."
        cleanup_netns
        echo "       已清理（抓包文件保留在 ${PCAP}）"
    fi
    return "${PASSED}"
}

parse_args "$@"
case "${MODE}" in
    netns) run_netns ;;
    server) run_server ;;
    client) run_client ;;
    *) echo "[ERROR] 未知模式"; exit 1 ;;
esac
