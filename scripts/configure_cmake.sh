#!/usr/bin/env bash
# ============================================================================
#  在 Ubuntu 虚拟机中配置 securityTransfer 的 CMake 工程
#
#  这个脚本只做三件事：
#    1. 检查 CMake / 编译器 / make / ctest 是否齐全，并打印版本
#    2. 用固定参数配置 build/ 目录（源码外构建，避免污染源码树）
#    3. 可选地编译、运行测试
#
#  用法：
#      bash scripts/configure_cmake.sh                 # 只配置
#      bash scripts/configure_cmake.sh --build         # 配置 + 编译
#      bash scripts/configure_cmake.sh --build --test  # 配置 + 编译 + ctest
#      bash scripts/configure_cmake.sh --clean --build # 先清空 build/ 再配置编译
#
#  可选环境变量：
#      BUILD_TYPE=Debug   指定构建类型（默认 Release）
#      GENERATOR=Ninja    指定 CMake 生成器（默认 Unix Makefiles）
#                         （使用 Ninja 需要先 sudo apt-get install -y ninja-build）
#      JOBS=4             并行编译任务数（默认 nproc）
# ============================================================================

set -uo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${project_root}/build"
build_type="${BUILD_TYPE:-Release}"
generator="${GENERATOR:-}"
jobs="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
min_cmake_version="3.10"

do_build=0
do_test=0
do_clean=0

for arg in "$@"; do
    case "${arg}" in
        --build) do_build=1 ;;
        --test)  do_test=1; do_build=1 ;;
        --clean) do_clean=1 ;;
        -h|--help)
            sed -n '2,22p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "[ERROR] 未知参数：${arg}（可用 --build / --test / --clean / --help）"
            exit 2
            ;;
    esac
done

echo '=================== 1. 检查工具链 ==================='
missing=0
for tool in cmake make c++ ctest; do
    if command -v "${tool}" >/dev/null 2>&1; then
        printf '  %-6s -> %s\n' "${tool}" "$(command -v "${tool}")"
    else
        printf '  %-6s -> 缺失\n' "${tool}"
        missing=1
    fi
done

if [ "${missing}" -ne 0 ]; then
    echo
    echo '[ERROR] 缺少构建工具，请先执行：'
    echo '    sudo apt-get update'
    echo '    sudo apt-get install -y cmake build-essential'
    exit 1
fi

cmake_version="$(cmake --version | head -n1 | awk '{print $3}')"
echo "  cmake 版本: ${cmake_version}（要求 >= ${min_cmake_version}）"
if ! printf '%s\n%s\n' "${min_cmake_version}" "${cmake_version}" | sort -V -C; then
    echo "[ERROR] CMake 版本过低：${cmake_version} < ${min_cmake_version}"
    exit 1
fi
# 注意：head 提前关闭管道会让 make/g++ 收到 SIGPIPE 并打印 "write error: stdout"，
# 因此这里把它们的 stderr 丢掉，只保留版本号。
echo "  c++    : $(c++ --version 2>/dev/null | head -n1)"
echo "  make   : $(make --version 2>/dev/null | head -n1)"
echo "  并行数 : ${jobs}"

echo
echo '=================== 2. 配置 CMake 工程 ==================='
echo "  源码目录: ${project_root}"
echo "  构建目录: ${build_dir}"
echo "  构建类型: ${build_type}"
[ -n "${generator}" ] && echo "  生成器  : ${generator}"

if [ "${do_clean}" -eq 1 ]; then
    # 只允许清理项目目录内部的 build/，避免误删其它路径
    case "${build_dir}" in
        "${project_root}"/*) echo "  清理    : 删除 ${build_dir}"; rm -rf "${build_dir}" ;;
        *) echo '[ERROR] 构建目录不在项目目录内，拒绝执行清理'; exit 1 ;;
    esac
fi

mkdir -p "${build_dir}"

generator_args=()
if [ -n "${generator}" ]; then
    generator_args=(-G "${generator}")
fi

cmake -S "${project_root}" -B "${build_dir}" \
      "${generator_args[@]}" \
      -DCMAKE_BUILD_TYPE="${build_type}" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
configure_status=$?
if [ "${configure_status}" -ne 0 ]; then
    echo "[ERROR] cmake 配置失败（退出码 ${configure_status}）"
    exit "${configure_status}"
fi
echo '[PASS] cmake 配置成功'

if [ "${do_build}" -eq 1 ]; then
    echo
    echo '=================== 3. 编译 ==================='
    cmake --build "${build_dir}" -j "${jobs}"
    build_status=$?
    if [ "${build_status}" -ne 0 ]; then
        echo "[ERROR] 编译失败（退出码 ${build_status}）"
        exit "${build_status}"
    fi
    echo '[PASS] 编译成功'
    for target in alice bob; do
        if [ -x "${build_dir}/${target}" ]; then
            echo "[PASS] 生成可执行文件 ${target}"
        else
            echo "[ERROR] 缺少可执行文件 ${target}"
            exit 1
        fi
    done
fi

if [ "${do_test}" -eq 1 ]; then
    echo
    echo '=================== 4. 运行测试 ==================='
    ( cd "${build_dir}" && ctest --output-on-failure )
    test_status=$?
    if [ "${test_status}" -ne 0 ]; then
        echo "[ERROR] 测试失败（退出码 ${test_status}）"
        exit "${test_status}"
    fi
    echo '[PASS] 测试全部通过'
fi

echo
echo '配置完成。后续常用命令：'
echo "  cmake --build ${build_dir} -j${jobs}          # 重新编译"
echo "  cd ${build_dir} && ctest --output-on-failure  # 运行测试"
echo "  cd ${build_dir} && ./bob  /  ./alice          # 运行 Alice / Bob"
echo "  ccmake ${project_root}                        # 终端下可视化修改 CMake 选项（需 cmake-curses-gui）"
echo "  ctest --version                               # 本机 CMake/CTest 版本：${cmake_version}"
