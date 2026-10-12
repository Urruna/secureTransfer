# ============================================================================
#  SecureTransfer 测试
#
#  运行方式（在 build 目录中）：
#      ctest --output-on-failure
#  或单独运行某个测试：
#      ./tests/test_packet
#      ./tests/test_secure_roundtrip
#      ...
# ============================================================================

find_package(Threads REQUIRED)

# 每个测试都是一个独立的可执行文件，便于单独调试；
# 统一链接安全层静态库（它已经带出协议层 / 密码层 / 网络层）与线程库。
function(st_add_test target_name source_file)
    add_executable(${target_name} ${source_file})
    target_link_libraries(${target_name} PRIVATE st_application Threads::Threads)
    target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

    add_test(NAME ${target_name} COMMAND ${target_name})
    set_tests_properties(${target_name} PROPERTIES TIMEOUT 180)
endfunction()

# ---------------- 第一阶段回归测试（网络层，必须继续全绿）----------------
st_add_test(test_frame unit/test_frame.cpp)
st_add_test(test_network unit/test_network.cpp)
st_add_test(test_tcp_roundtrip integration/test_tcp_roundtrip.cpp)

# ---------------- 第一部分标准向量回归（AES + CMAC，纯 C++）----------------
add_executable(test_aes_cmac unit/test_aes_cmac.cpp)
target_link_libraries(test_aes_cmac PRIVATE st_security)
target_include_directories(test_aes_cmac PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME test_aes_cmac COMMAND test_aes_cmac)
set_tests_properties(test_aes_cmac PROPERTIES TIMEOUT 60)

# ---------------- 第二部分单元测试 ----------------
st_add_test(test_packet unit/test_packet.cpp)
st_add_test(test_transcript unit/test_transcript.cpp)
st_add_test(test_replay_guard unit/test_replay_guard.cpp)
st_add_test(test_session_state unit/test_session_state.cpp)
st_add_test(test_transfer_meta unit/test_transfer_meta.cpp)
st_add_test(test_access_control unit/test_access_control.cpp)
st_add_test(test_reject_gate unit/test_reject_gate.cpp)

# ---------------- 第二部分集成测试 ----------------
st_add_test(test_secure_roundtrip integration/test_secure_roundtrip.cpp)
st_add_test(test_file_transfer integration/test_file_transfer.cpp)
st_add_test(test_access_control_e2e integration/test_access_control.cpp)

# ---------------- 第二部分安全测试（篡改 / 伪造 / 重放）----------------
st_add_test(test_tamper integration/test_tamper.cpp)
st_add_test(test_forge integration/test_forge.cpp)
st_add_test(test_replay integration/test_replay.cpp)
# 链路中间人：不再由端点"自己改自己的发送路径"，而是独立的转发者（第三部分 Eve）
st_add_test(test_mitm integration/test_mitm.cpp)
