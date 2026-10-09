# ============================================================================
#  SecureTransfer - 安全的信息传输套件
#  第二部分：安全通信协议与网络
#
#  构建方式（Ubuntu 20.04 / 621 虚拟机）：
#      cd /home/securityTransfer
#      mkdir -p build && cd build
#      cmake .. && cmake --build . -j4
#      ctest --output-on-failure
#
#  生成的可执行文件：
#      build/alice / build/bob
#      build/tests/test_* （可用 ctest 运行）
# ============================================================================

cmake_minimum_required(VERSION 3.16)

project(SecureTransfer
        VERSION 0.2.0
        DESCRIPTION "SecureTransfer - 安全的信息传输套件（网络安全协议部分）"
        LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra)
endif()

# ---------------------------------------------------------------------------
# 网络层（第一阶段成果，本阶段不做修改）
# ---------------------------------------------------------------------------
add_library(st_network STATIC
        src/network/frame.cpp
        src/network/network.cpp)
target_include_directories(st_network PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Windows 下 Winsock 需要显式链接 ws2_32（Linux 侧不需要）
if(WIN32)
    target_link_libraries(st_network PUBLIC ws2_32)
endif()

# ---------------------------------------------------------------------------
# 密码层
#   * aes.cpp / cmac.cpp —— 第一部分交付的自实现算法（原样导入）
#   * placeholder_mac_engine.cpp / mock_crypto_provider.cpp —— 开发期占位实现
#   * aes_crypto_provider.cpp —— 把算法接到协议层的 CryptoProvider 接口
# ---------------------------------------------------------------------------
add_library(st_crypto STATIC
        src/common/random.cpp
        src/common/console.cpp
        src/common/text_encoding.cpp
        src/crypto/aes.cpp
        src/crypto/cmac.cpp
        src/crypto/placeholder_mac_engine.cpp
        src/crypto/mock_crypto_provider.cpp
        src/crypto/aes_crypto_provider.cpp)
target_include_directories(st_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Windows 下 BCryptGenRandom 需要显式链接 bcrypt（Linux 侧不链接任何库）
if(WIN32)
    target_link_libraries(st_crypto PUBLIC bcrypt)
endif()

# ---------------------------------------------------------------------------
# 协议层：统一数据包格式 + 握手转录串
# ---------------------------------------------------------------------------
add_library(st_protocol STATIC
        src/protocol/packet.cpp
        src/protocol/transcript.cpp)
target_link_libraries(st_protocol PUBLIC st_network st_crypto)

# ---------------------------------------------------------------------------
# 安全层：密钥读取 / 防重放 / 握手与会话
# ---------------------------------------------------------------------------
add_library(st_security STATIC
        src/security/access_control.cpp
        src/security/attack_report.cpp
        src/security/keystore.cpp
        src/security/replay_guard.cpp
        src/security/session.cpp)
target_link_libraries(st_security PUBLIC st_protocol)

# ---------------------------------------------------------------------------
# 应用层（第三部分）：文件 / 图像安全传输
#   * 复用安全数据通道（sendMessage），因此自动获得加密 / CMAC / 防重放
#   * 只新增"分块重组 + 整文件 CRC32 校验"这一层应用逻辑
# ---------------------------------------------------------------------------
add_library(st_application STATIC
        src/application/transfer_meta.cpp
        src/application/file_transfer.cpp)
target_link_libraries(st_application PUBLIC st_security)

# ---------------------------------------------------------------------------
# Alice / Bob 演示程序
# ---------------------------------------------------------------------------
add_executable(bob apps/bob/main.cpp)
target_link_libraries(bob PRIVATE st_application)

add_executable(alice apps/alice/main.cpp)
target_link_libraries(alice PRIVATE st_application)

# ---------------------------------------------------------------------------
# 图形界面（第三部分，课程要求 8）
#   * 只有装好 Qt5（qtbase5-dev）时才会构建；没装则自动跳过，不影响其它目标
#   * 界面本身不实现任何密码学逻辑，只调用已有的安全会话 / 文件传输 / 访问控制
# ---------------------------------------------------------------------------
find_package(Qt5 COMPONENTS Widgets QUIET)
if(Qt5_FOUND)
    find_package(Threads REQUIRED)
    add_executable(st_ui
            apps/ui/main.cpp
            apps/ui/main_window.cpp
            apps/ui/session_worker.cpp)
    set_target_properties(st_ui PROPERTIES AUTOMOC ON)
    target_include_directories(st_ui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/apps/ui)
    target_link_libraries(st_ui PRIVATE st_application Qt5::Widgets Threads::Threads)
    message(STATUS "已启用图形界面目标 st_ui（Qt ${Qt5Widgets_VERSION}）")
else()
    message(STATUS "未找到 Qt5 Widgets，跳过图形界面目标 st_ui（不影响命令行程序）")
endif()

# ---------------------------------------------------------------------------
# 性能测试工具（第一部分成果的加工程序，不参与 ctest）
# ---------------------------------------------------------------------------
add_executable(cmac_benchmark tools/cmac_benchmark.cpp)
target_link_libraries(cmac_benchmark PRIVATE st_crypto)

# ---------------------------------------------------------------------------
# 与库实现的性能对比工具（课程要求 5）
#   ⚠ 只用于对比实验：这些目标链接密码库，但系统本体（alice/bob/st_*）不链接，
#     密码算法仍然全部是第一部分自己实现的（课程要求 4）。
#   后端都是"可选"的：某个库找不到就自动跳过该后端，不影响其它目标构建。
#
#   两个可执行文件：
#     * crypto_benchmark      —— 用发行包里的库（默认可能启用硬件加速）；
#     * crypto_benchmark_soft —— "纯软件对纯软件"对照，链接自建的、禁用 AES-NI 的
#                                Mbed TLS / Botan（需要 -DST_BENCH_SOFT_ROOT=<前缀目录>）。
# ---------------------------------------------------------------------------
find_package(OpenSSL QUIET)
find_package(PkgConfig QUIET)

set(ST_BENCH_SOURCES
        tools/crypto_benchmark.cpp
        tools/bench_backend_self.cpp)
set(ST_BENCH_DEFS "")
set(ST_BENCH_LIBS "")

if(OpenSSL_FOUND)
    list(APPEND ST_BENCH_SOURCES tools/bench_backend_openssl.cpp)
    list(APPEND ST_BENCH_DEFS ST_BENCH_WITH_OPENSSL)
    list(APPEND ST_BENCH_LIBS OpenSSL::Crypto)
    message(STATUS "已启用 crypto_benchmark 的 OpenSSL 后端（OpenSSL ${OPENSSL_VERSION}）")
endif()

if(PkgConfig_FOUND)
    pkg_check_modules(MBEDTLS QUIET IMPORTED_TARGET mbedtls)
    pkg_check_modules(MBEDCRYPTO QUIET IMPORTED_TARGET mbedcrypto)
    pkg_check_modules(BOTAN QUIET IMPORTED_TARGET botan-3)
endif()

if(MBEDTLS_FOUND)
    list(APPEND ST_BENCH_SOURCES tools/bench_backend_mbedtls.cpp)
    list(APPEND ST_BENCH_DEFS ST_BENCH_WITH_MBEDTLS)
    list(APPEND ST_BENCH_LIBS PkgConfig::MBEDTLS)
    if(MBEDCRYPTO_FOUND)
        list(APPEND ST_BENCH_LIBS PkgConfig::MBEDCRYPTO)
    endif()
    message(STATUS "已启用 crypto_benchmark 的 Mbed TLS 后端（${MBEDTLS_VERSION}）")
endif()

if(BOTAN_FOUND)
    list(APPEND ST_BENCH_SOURCES tools/bench_backend_botan.cpp)
    list(APPEND ST_BENCH_DEFS ST_BENCH_WITH_BOTAN)
    list(APPEND ST_BENCH_LIBS PkgConfig::BOTAN)
    message(STATUS "已启用 crypto_benchmark 的 Botan 后端（${BOTAN_VERSION}）")
endif()

if(OpenSSL_FOUND OR MBEDTLS_FOUND OR BOTAN_FOUND)
    add_executable(crypto_benchmark ${ST_BENCH_SOURCES})
    target_link_libraries(crypto_benchmark PRIVATE st_crypto ${ST_BENCH_LIBS})
    target_compile_definitions(crypto_benchmark PRIVATE ${ST_BENCH_DEFS})
    # Botan 3 要求 C++20：只给这一个目标开，其余代码仍是 C++17。
    if(BOTAN_FOUND)
        target_compile_features(crypto_benchmark PRIVATE cxx_std_20)
    endif()
    # 该工具刻意使用 OpenSSL 的经典 CMAC_* 接口（与虚拟机里的 OpenSSL 1.1.1 行为一致）；
    # 在 OpenSSL 3.x 上这些接口被标记为“已弃用”，这里只对这些目标关闭该提示。
    if(NOT MSVC)
        target_compile_options(crypto_benchmark PRIVATE -Wno-deprecated-declarations)
    endif()
    message(STATUS "已生成 crypto_benchmark")
else()
    message(STATUS "未找到 OpenSSL，跳过 crypto_benchmark（仅影响性能对比工具）")
endif()

# ---- 纯软件对照（方案 b）：链接自建的、禁用 AES-NI 的 Mbed TLS / Botan ----
set(ST_BENCH_SOFT_ROOT "" CACHE PATH
    "无 AES-NI 版 Mbed TLS / Botan 的前缀目录，例如 D:/AppGallery/dev-tools/libs")
if(ST_BENCH_SOFT_ROOT AND (OpenSSL_FOUND OR MBEDTLS_FOUND OR BOTAN_FOUND))
    set(ST_BENCH_SOFT_SOURCES
            tools/crypto_benchmark.cpp
            tools/bench_backend_self.cpp
            tools/bench_backend_openssl.cpp
            tools/bench_backend_mbedtls.cpp
            tools/bench_backend_botan.cpp)
    add_executable(crypto_benchmark_soft ${ST_BENCH_SOFT_SOURCES})
    target_link_libraries(crypto_benchmark_soft PRIVATE
            st_crypto
            OpenSSL::Crypto
            "${ST_BENCH_SOFT_ROOT}/mbedtls-noaesni/lib/libmbedcrypto_noaesni.a"
            "${ST_BENCH_SOFT_ROOT}/botan-noaesni/lib/botan-3.lib"
            ws2_32)
    target_include_directories(crypto_benchmark_soft PRIVATE
            "${ST_BENCH_SOFT_ROOT}/mbedtls-noaesni/include"
            "${ST_BENCH_SOFT_ROOT}/botan-noaesni/include/botan-3")
    target_compile_definitions(crypto_benchmark_soft PRIVATE
            ST_BENCH_WITH_OPENSSL ST_BENCH_WITH_MBEDTLS ST_BENCH_WITH_BOTAN ST_BENCH_BOTAN_SOFT
            # 让后端 TU 与"无 AES-NI"那份库使用同一个配置头（否则结构体/特性会不一致）
            MBEDTLS_CONFIG_FILE="mbedtls/mbedtls_config_noaesni.h")
    target_compile_features(crypto_benchmark_soft PRIVATE cxx_std_20)
    if(NOT MSVC)
        target_compile_options(crypto_benchmark_soft PRIVATE -Wno-deprecated-declarations)
    endif()
    message(STATUS "已生成 crypto_benchmark_soft（纯软件对照，前缀：${ST_BENCH_SOFT_ROOT}）")
endif()

# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------
include(CTest)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
