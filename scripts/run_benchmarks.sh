#!/usr/bin/env bash
# ============================================================================
#  SecureTransfer - 一键跑完性能对比（默认 + 纯软件对照）并生成汇总表
#
#  用途（课程要求 5）：跑出"自实现 vs OpenSSL vs Mbed TLS vs Botan"的完整数据，
#  并把两次运行合并成一张汇总表（相对自实现的倍率）。
#
#  用法（在 MSYS2 的 MinGW64 shell 里执行，Windows 侧）：
#      bash scripts/run_benchmarks.sh                 # 跑 100 MB，输出到 experiment_data/benchmarks/
#      bash scripts/run_benchmarks.sh --max-mb 10     # 快速版
#
#  前置条件：
#      * 默认目标需要：OpenSSL + Mbed TLS + Botan（MSYS2：pacman -S mingw-w64-x86_64-mbedtls mingw-w64-x86_64-libbotan）
#      * 纯软件目标 crypto_benchmark_soft 需要先自建"禁用 AES-NI"的库，
#        并在 CMake 配置时指定：-DST_BENCH_SOFT_ROOT=<前缀目录>
#        （做法见 docs/performance.md 的"纯软件对照怎么来的"一节）
# ============================================================================
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build-win"
OUT_DIR="${PROJECT_DIR}/experiment_data/benchmarks"
MAX_MB=100

while [ $# -gt 0 ]; do
    case "$1" in
        --max-mb) MAX_MB="${2:-100}"; shift 2 ;;
        *) shift ;;
    esac
done

mkdir -p "${OUT_DIR}"

echo "=================== 1. 默认（各库按默认启用硬件加速）==================="
"${BUILD_DIR}/crypto_benchmark.exe" --max-mb "${MAX_MB}" \
    --csv "${OUT_DIR}/bench_hw.csv" --label hw > "${OUT_DIR}/bench_hw.log" 2>&1
echo "  退出码=$?  输出=${OUT_DIR}/bench_hw.log"

if [ -x "${BUILD_DIR}/crypto_benchmark_soft.exe" ]; then
    echo
    echo "=================== 2. 纯软件对照（无 AES-NI 构建 + OPENSSL_ia32cap）==================="
    OPENSSL_ia32cap='~0x200000200000000' "${BUILD_DIR}/crypto_benchmark_soft.exe" \
        --max-mb "${MAX_MB}" --csv "${OUT_DIR}/bench_sw.csv" --label sw \
        > "${OUT_DIR}/bench_sw.log" 2>&1
    echo "  退出码=$?  输出=${OUT_DIR}/bench_sw.log"

    echo
    echo "=================== 3. 汇总表 ==================="
    if command -v python3 >/dev/null 2>&1; then
        python3 "${PROJECT_DIR}/tools/bench_merge.py" \
            "${OUT_DIR}/bench_hw.csv" "${OUT_DIR}/bench_sw.csv" \
            -o "${OUT_DIR}/summary.md"
    else
        echo "  [提示] 没找到 python3，跳过汇总（CSV 已生成，可手工汇总）"
    fi
else
    echo
    echo "[提示] 没有 crypto_benchmark_soft.exe（未配置 -DST_BENCH_SOFT_ROOT），只生成了默认数据"
fi

echo
echo "完成。文件都在 ${OUT_DIR}/"
