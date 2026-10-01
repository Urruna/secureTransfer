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
#   ⚠ 只用于对比实验：该目标链接 OpenSSL，但系统本体（alice/bob/st_*）不链接，
#     密码算法仍然全部是第一部分自己实现的（课程要求 4）。
#   未安装 libssl-dev 时自动跳过，不影响其它目标的构建。
# ---------------------------------------------------------------------------
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    add_executable(crypto_benchmark tools/crypto_benchmark.cpp)
    target_link_libraries(crypto_benchmark PRIVATE st_crypto OpenSSL::Crypto)
    # 该工具刻意使用 OpenSSL 的经典 CMAC_* 接口（与虚拟机里的 OpenSSL 1.1.1 行为一致）；
    # 在 OpenSSL 3.x 上这些接口被标记为“已弃用”，这里只对这一个目标关闭该提示。
    if(NOT MSVC)
        target_compile_options(crypto_benchmark PRIVATE -Wno-deprecated-declarations)
    endif()
    message(STATUS "已启用 crypto_benchmark（OpenSSL ${OPENSSL_VERSION}）")
else()
    message(STATUS "未找到 OpenSSL，跳过 crypto_benchmark（仅影响性能对比工具）")
endif()

# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------
include(CTest)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
