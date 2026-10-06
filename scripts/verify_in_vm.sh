#!/usr/bin/env bash
# ============================================================================
#  SecureTransfer - 一键验证脚本（在 Ubuntu 虚拟机内运行）
#
#  流程：检查工具链 → 编译 → 运行全部测试 → 跑一次 Alice/Bob 安全通信演示
#        →（可选）运行篡改/伪造/重放攻击测试
#
#  用法：
#      bash scripts/verify_in_vm.sh
#      bash scripts/verify_in_vm.sh --no-demo      # 只编译与测试
# ============================================================================
set -u

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
RUN_DEMO=1

for arg in "$@"; do
    case "${arg}" in
        --no-demo) RUN_DEMO=0 ;;
    esac
done

echo "=================== 0. 环境检查 ==================="
echo "项目目录 : ${PROJECT_DIR}"
g++ --version | head -1
cmake --version | head -1

echo
echo "=================== 1. 编译 ==================="
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
cmake .. >/tmp/st_cmake.log 2>&1 || { echo "[FAIL] cmake 配置失败"; tail -30 /tmp/st_cmake.log; exit 1; }
if cmake --build . -j4 >/tmp/st_build.log 2>&1; then
    echo "[PASS] 编译成功"
else
    echo "[FAIL] 编译失败"
    tail -60 /tmp/st_build.log
    exit 1
fi
for exe in alice bob; do
    if [ -x "${BUILD_DIR}/${exe}" ]; then
        echo "[PASS] 生成可执行文件 ${exe}"
    else
        echo "[FAIL] 缺少可执行文件 ${exe}"
        exit 1
    fi
done

echo
echo "=================== 2. 自动化测试 ==================="
if ctest --output-on-failure; then
    echo "[PASS] ctest 全部通过"
else
    echo "[FAIL] ctest 存在失败用例"
    exit 1
fi

if [ "${RUN_DEMO}" -eq 0 ]; then
    echo
    echo "[INFO] 已跳过演示（--no-demo）"
    exit 0
fi

echo
echo "=================== 3. Alice / Bob 安全通信演示 ==================="
PORT=$(( (RANDOM % 2000) + 9000 ))
cd "${BUILD_DIR}"
./bob "${PORT}" --once --quiet >/tmp/st_bob_demo.log 2>&1 &
BOB_PID=$!
sleep 1
./alice 127.0.0.1 "${PORT}" --quiet >/tmp/st_alice_demo.log 2>&1
ALICE_RC=$?
wait "${BOB_PID}" 2>/dev/null
BOB_RC=$?

echo "---------- Bob 输出 ----------"
cat /tmp/st_bob_demo.log
echo "---------- Alice 输出 ----------"
cat /tmp/st_alice_demo.log

if [ "${ALICE_RC}" -eq 0 ] && [ "${BOB_RC}" -eq 0 ]; then
    echo "[PASS] Alice / Bob 都正常退出"
else
    echo "[FAIL] Alice 退出码=${ALICE_RC}, Bob 退出码=${BOB_RC}"
    exit 1
fi

echo
echo "=================== 4. 安全测试（篡改 / 伪造 / 重放）==================="
for test in test_tamper test_forge test_replay; do
    if "${BUILD_DIR}/tests/${test}" >/tmp/st_${test}.log 2>&1; then
        echo "[PASS] ${test}"
    else
        echo "[FAIL] ${test}"
        cat /tmp/st_${test}.log
        exit 1
    fi
done

echo
echo "=================== 5. 文件 / 图像传输演示与校验 ==================="
DATA_DIR="${PROJECT_DIR}/experiment_data"
OUT_DIR="${DATA_DIR}/received"
if [ -d "${DATA_DIR}" ] && [ -f "${DATA_DIR}/test_file_1MB.bin" ]; then
    FILE_PORT=$(( (RANDOM % 2000) + 9500 ))
    rm -rf "${OUT_DIR}"
    mkdir -p "${OUT_DIR}"
    cd "${BUILD_DIR}"
./bob "${FILE_PORT}" --out-dir "${OUT_DIR}" --once --quiet >/tmp/st_ft_bob.log 2>&1 &
    FT_BOB_PID=$!
    sleep 1
    ./alice 127.0.0.1 "${FILE_PORT}" --quiet \
        --file "${DATA_DIR}/test_file_64KB.bin" \
        --file "${DATA_DIR}/test_file_1MB.bin" \
        --image "${DATA_DIR}/test_image_256x256.png" \
        --image "${DATA_DIR}/test_image_1024x768.png" >/tmp/st_ft_alice.log 2>&1
    FT_ALICE_RC=$?
    wait "${FT_BOB_PID}" 2>/dev/null
    FT_BOB_RC=$?

    grep -E "文件名|大小|传输方式|分块数量|整文件 CRC32|应用层吞吐" /tmp/st_ft_alice.log | head -24
    echo "接收端校验：" 
    grep -E "校验结果" /tmp/st_ft_bob.log

    FT_OK=1
    if [ "${FT_ALICE_RC}" -eq 0 ] && [ "${FT_BOB_RC}" -eq 0 ]; then
        for f in test_file_64KB.bin test_file_1MB.bin test_image_256x256.png test_image_1024x768.png; do
            if cmp -s "${DATA_DIR}/${f}" "${OUT_DIR}/${f}"; then
                echo "[PASS] ${f} 逐字节一致"
            else
                echo "[FAIL] ${f} 与源文件不一致"
                FT_OK=0
            fi
        done
    else
        echo "[FAIL] 文件传输演示失败：Alice=${FT_ALICE_RC}, Bob=${FT_BOB_RC}"
        FT_OK=0
    fi
    if [ "${FT_OK}" -ne 1 ]; then
        exit 1
    fi
    echo "文件 / 图像传输：4 个文件全部通过（含 1 MB 文件与 2.2 MB 图像）"
else
    echo "[WARN] 未找到 experiment_data/ 目录，跳过文件与图像传输演示"
fi

echo
echo "=================== 6. 访问控制演示（管理员 vs 访客）==================="
AC_PORT_ADMIN=$(( (RANDOM % 1000) + 10600 ))
AC_PORT_GUEST=$(( AC_PORT_ADMIN + 1 ))
ACCESS_LOG="${DATA_DIR}/access_log.txt"
AC_POLICY="${PROJECT_DIR}/configs/access_policy.conf"
if [ -f "${AC_POLICY}" ]; then
    cd "${BUILD_DIR}"
    # 场景 1：管理员（alice）——全部允许，并可查看审计日志
    ./bob "${AC_PORT_ADMIN}" --peer alice --out-dir "${OUT_DIR}" --access-log "${ACCESS_LOG}" \
        --once --quiet >/tmp/st_ac_bob1.log 2>&1 &
    AC_BOB1=$!
    sleep 1
    ./alice 127.0.0.1 "${AC_PORT_ADMIN}" --id alice --quiet --whoami --view-log \
        --file "${DATA_DIR}/test_file_64KB.bin" >/tmp/st_ac_alice1.log 2>&1
    AC_A1=$?
    wait "${AC_BOB1}" 2>/dev/null

    # 场景 2：访客（mallory）——短消息允许，文件与查看日志被拒绝，会话继续
    ./bob "${AC_PORT_GUEST}" --peer mallory --out-dir "${OUT_DIR}" --access-log "${ACCESS_LOG}" \
        --once --quiet >/tmp/st_ac_bob2.log 2>&1 &
    AC_BOB2=$!
    sleep 1
    ./alice 127.0.0.1 "${AC_PORT_GUEST}" --id mallory --quiet --whoami --view-log \
        --file "${DATA_DIR}/test_file_64KB.bin" >/tmp/st_ac_alice2.log 2>&1
    AC_A2=$?
    wait "${AC_BOB2}" 2>/dev/null

    echo "---------- 场景 1（管理员 alice）----------"
    grep -E "本端角色|服务端返回|对端确认" /tmp/st_ac_alice1.log
    echo "---------- 场景 2（访客 mallory）----------"
    grep -E "本端角色|本地提示|服务端返回|对端确认" /tmp/st_ac_alice2.log
    echo "---------- 服务端判定（场景 2）----------"
    grep -E "访问控制拒绝|共接收" /tmp/st_ac_bob2.log

    if [ "${AC_A1}" -eq 0 ] && [ "${AC_A2}" -eq 0 ] &&
       grep -q "ACCESS DENIED" /tmp/st_ac_alice2.log &&
       grep -q "DENY" "${ACCESS_LOG}"; then
        echo "[PASS] 访问控制：管理员允许、访客被拒绝，且审计日志已记录 DENY"
    else
        echo "[FAIL] 访问控制演示未达到预期（Alice 退出码 ${AC_A1}/${AC_A2}）"
        exit 1
    fi
else
    echo "[WARN] 未找到 ${AC_POLICY}，跳过访问控制演示"
fi

echo
echo "全部验证通过。"
echo "提示：如需演示窃听攻击，运行 bash scripts/capture_eve.sh ${PORT} 'Hello Bob'"
