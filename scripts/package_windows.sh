#!/usr/bin/env bash
# ============================================================================
#  SecureTransfer - Windows 打包脚本（在 MSYS2 的 MinGW64 shell 里运行）
#
#  作用：把 alice.exe / bob.exe / st_ui.exe 连同全部依赖
#        （Qt5 DLL 与平台插件、MinGW 运行时 DLL、配置模板、实验数据）
#        复制到 dist/securityTransfer/，使其脱离 MSYS2 环境也能双击运行。
#
#  用法：
#      bash scripts/package_windows.sh                 # 输出到 dist/securityTransfer
#      bash scripts/package_windows.sh /d/demo/pack    # 输出到指定目录
#
#  前置条件：
#      * MSYS2：mingw-w64-x86_64-gcc / cmake / ninja
#      * MSYS2：mingw-w64-x86_64-qt5（提供 windeployqt-qt5.exe）
#
#  说明：
#      * dist/ 已被 .gitignore 排除（几十 MB 的 DLL 不入库），需要时重新跑本脚本即可；
#      * **不会**打包 configs/keys.conf（里面有 K_master）：发布包只带
#        keys.conf.example，使用者需自己复制一份并填好密钥（脚本会打印提示）。
# ============================================================================
set -euo pipefail

export MSYSTEM=MINGW64
export PATH=/mingw64/bin:/usr/bin:$PATH

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build-win"
DIST_DIR="${1:-${PROJECT_DIR}/dist/securityTransfer}"

# windeployqt-qt5 会先跑 qmake 并把输出写进临时文件；在受限环境里系统临时目录
# 可能不可写（会报 "Error creating stdout temporary file"），这里统一指向构建目录。
export TMPDIR="${PROJECT_DIR}/build-win/package-tmp"
export TEMP="${TMPDIR}"
export TMP="${TMPDIR}"
mkdir -p "${TMPDIR}"

echo "项目目录 : ${PROJECT_DIR}"
echo "构建目录 : ${BUILD_DIR}"
echo "输出目录 : ${DIST_DIR}"

echo
echo "=================== 1. 构建（Release） ==================="
cmake -S "${PROJECT_DIR}" -B "${BUILD_DIR}" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "${BUILD_DIR}" -j8

echo
echo "=================== 2. 复制可执行文件 ==================="
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"
for exe in alice bob st_ui; do
    cp "${BUILD_DIR}/${exe}.exe" "${DIST_DIR}/"
    echo "  + ${exe}.exe"
done

echo
echo "=================== 3. windeployqt（Qt5 DLL / 插件） ==================="
# 注意：windeployqt 在缺少"可选"依赖（例如 libGLESv2.dll，纯 Widgets 程序用不到）
# 时会打印一行提示并返回非零码，所以这里不因为它中断打包。
set +e
windeployqt-qt5.exe --release --no-translations --no-system-d3d-compiler --no-opengl-sw \
    "${DIST_DIR}/st_ui.exe" 2>&1 | sed 's/^/  /'
WINDEPLOY_RC="${PIPESTATUS[0]}"
set -e
if [ "${WINDEPLOY_RC}" -ne 0 ]; then
    echo "  [WARN] windeployqt 退出码 ${WINDEPLOY_RC}（通常是缺少可选的 libGLESv2.dll）——"
    echo "         注意：它可能因此提前中断，下面的步骤 3.1 会补齐缺失的插件"
fi

echo
echo "=================== 3.1 校验并补齐 Qt 插件 ==================="
# windeployqt 一旦遇到缺失依赖就会提前返回，可能还没来得及复制插件目录；
# 而 Qt 程序**没有 platforms/qwindows.dll 就根本起不来**（报
# "no Qt platform plugin could be initialized"），所以这里做一次兜底校验。
QT_PLUGIN_DIR="/mingw64/share/qt5/plugins"
copy_plugin_if_missing() {
    local subdir="$1" file="$2"
    if [ -f "${DIST_DIR}/${subdir}/${file}" ]; then
        echo "  = ${subdir}/${file}（windeployqt 已部署）"
        return
    fi
    if [ -f "${QT_PLUGIN_DIR}/${subdir}/${file}" ]; then
        mkdir -p "${DIST_DIR}/${subdir}"
        cp "${QT_PLUGIN_DIR}/${subdir}/${file}" "${DIST_DIR}/${subdir}/"
        echo "  + ${subdir}/${file}（手动补齐）"
    else
        echo "  ! 找不到 ${QT_PLUGIN_DIR}/${subdir}/${file}"
    fi
}

copy_plugin_if_missing "platforms" "qwindows.dll"   # 必需：Windows 平台插件
copy_plugin_if_missing "styles" "qwindowsvistastyle.dll"
copy_plugin_if_missing "imageformats" "qico.dll"

echo
echo "=================== 4. 补齐 MinGW 运行时 DLL（依赖传递闭包） ==================="
# windeployqt 只负责 Qt 自己的库，而且遇到缺失依赖时会提前退出，导致：
#   * 我们自己的 exe 缺 libstdc++-6 / libgcc_s_seh-1 / libwinpthread-1；
#   * Qt5Core/Gui/... 还缺一批 MinGW 运行时库（icu*、zlib1、harfbuzz、pcre2、
#     double-conversion、zstd、png16、md4c ...），少了任何一个都是 0xC0000135。
# 这里做"传递闭包"：反复扫描 dist 里所有 PE 文件的导入表，凡是 MSYS2
# （/mingw64/bin）里有的就复制过来，直到不再出现新的依赖。
for _pass in 1 2 3 4 5; do
    copied=0
    while IFS= read -r dll; do
        [ -z "${dll}" ] && continue
        [ -f "${DIST_DIR}/${dll}" ] && continue
        if [ -f "/mingw64/bin/${dll}" ]; then
            cp "/mingw64/bin/${dll}" "${DIST_DIR}/"
            echo "  + ${dll}"
            copied=$((copied + 1))
        fi
    done < <(find "${DIST_DIR}" -type f \( -name '*.exe' -o -name '*.dll' \) \
                 -exec objdump -p {} \; 2>/dev/null |
                 awk '/DLL Name:/ {print $3}' | sort -u)
    [ "${copied}" -eq 0 ] && break
done

echo
echo "=================== 4.1 校验：dist 里是否还缺非系统 DLL ==================="
missing_any=0
while IFS= read -r dll; do
    [ -z "${dll}" ] && continue
    [ -f "${DIST_DIR}/${dll}" ] && continue
    # 规则：MSYS2 里有、但我们没拷进来 = 真的缺；MSYS2 里也没有 = 视为 Windows 系统库
    if [ -f "/mingw64/bin/${dll}" ]; then
        echo "  [缺库] ${dll}"
        missing_any=1
    fi
done < <(find "${DIST_DIR}" -type f \( -name '*.exe' -o -name '*.dll' \) \
             -exec objdump -p {} \; 2>/dev/null |
             awk '/DLL Name:/ {print $3}' | sort -u)
if [ "${missing_any}" -eq 0 ]; then
    echo "  [ok] 所有非系统依赖都已打包"
fi

echo
echo "=================== 5. 配置模板与实验数据 ==================="
mkdir -p "${DIST_DIR}/configs" "${DIST_DIR}/experiment_data"
cp "${PROJECT_DIR}/configs/keys.conf.example" "${DIST_DIR}/configs/"
cp "${PROJECT_DIR}/configs/access_policy.conf" "${DIST_DIR}/configs/"
cp "${PROJECT_DIR}/configs/demo_config.conf" "${DIST_DIR}/configs/"
for f in "${PROJECT_DIR}"/experiment_data/test_file_*.bin \
         "${PROJECT_DIR}"/experiment_data/test_image_*.png \
         "${PROJECT_DIR}"/experiment_data/text_messages.txt \
         "${PROJECT_DIR}"/experiment_data/README.md; do
    if [ -f "$f" ]; then
        cp "$f" "${DIST_DIR}/experiment_data/"
    fi
done
echo "  + configs/（keys.conf.example / access_policy.conf / demo_config.conf）"
echo "  + experiment_data/（测试文件、图像、文本消息）"

echo
echo "=================== 6. 启动脚本（.bat） ==================="
# 批处理用 CRLF 换行，避免旧版 cmd.exe 解析异常
write_bat() {
    local path="$1"
    shift
    : > "${path}"
    for line in "$@"; do
        printf '%s\r\n' "${line}" >> "${path}"
    done
    echo "  + $(basename "${path}")"
}

write_bat "${DIST_DIR}/run_bob.bat" \
    "@echo off" "cd /d \"%~dp0\"" \
    "echo 启动服务端 Bob（默认端口 9000），按 Ctrl+C 结束" \
    "bob.exe 9000 %*"

write_bat "${DIST_DIR}/run_alice.bat" \
    "@echo off" "cd /d \"%~dp0\"" \
    "echo 启动客户端 Alice 连接 127.0.0.1:9000" \
    "alice.exe 127.0.0.1 9000 %*"

write_bat "${DIST_DIR}/run_ui.bat" \
    "@echo off" "cd /d \"%~dp0\"" \
    "echo 启动图形界面（Qt5）" \
    "start \"\" st_ui.exe %*"

echo
echo "=================== 7. 打包内容概览 ==================="
du -sh "${DIST_DIR}" | sed 's/^/  总大小: /'
ls "${DIST_DIR}" | sed 's/^/  /'

cat > "${DIST_DIR}/README.txt" <<'EOF'
SecureTransfer（Windows 发布包）
=================================

内容
----
  alice.exe / bob.exe      命令行客户端与服务端
  st_ui.exe                图形界面（Qt5，已带全部 DLL 与插件）
  run_bob.bat              启动服务端 Bob（端口 9000）
  run_alice.bat            启动客户端 Alice（连 127.0.0.1:9000）
  run_ui.bat               启动图形界面
  configs/                 密钥与访问控制策略（只带模板，见下）
  experiment_data/         测试用文件、图像与文本消息

第一步：配置密钥（必须）
------------------------
  1) 把 configs/keys.conf.example 复制成 configs/keys.conf；
  2) 填写 master_key（32 个十六进制字符 = 16 字节）；
  3) Alice 与 Bob 必须使用同一把 K_master，否则握手认证会失败。

  ⚠ 本发布包**不包含** keys.conf（避免密钥随包传播）。

运行
----
  命令行：先双击 run_bob.bat，再双击 run_alice.bat。
          （脚本会先把工作目录切到本目录，程序据此找到 configs/keys.conf）
  图形界面：直接双击 run_ui.bat。

  常见错误：0xC0000135（找不到 DLL）说明包不完整，请重新执行
  scripts/package_windows.sh 打包；若提示认证失败，请检查两端的 K_master。
EOF

cat <<'EOF'

=================== 使用说明（也会写入 README.txt） ===================
1) 把 configs/keys.conf.example 复制成 configs/keys.conf，填好 K_master
   （Alice 与 Bob 必须使用同一把 K_master，否则握手认证会失败）；
   命令行程序按 "相对当前目录的 configs/keys.conf" 查找密钥文件，
   所以请用 run_bob.bat / run_alice.bat 启动（它们会先切到本目录）。
2) 服务端先运行 run_bob.bat，客户端再运行 run_alice.bat。
3) 图形界面：直接双击 run_ui.bat（或 st_ui.exe）。
EOF
