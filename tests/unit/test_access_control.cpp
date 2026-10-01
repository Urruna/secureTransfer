// ============================================================================
//  SecureTransfer 测试 - 访问控制单元测试
//  file: tests/unit/test_access_control.cpp
//
//  覆盖：
//    * 策略解析（角色 / 权限 / 身份映射 / 默认角色）；
//    * 判定矩阵：管理员 / 普通用户 / 访客 / 未登记身份；
//    * 默认拒绝：未登记身份落到 defaultRole，角色未定义权限时无权限；
//    * 非法策略被拒绝（未知权限名、缺少默认角色定义等）；
//    * 消息类型 → 操作 的映射；
//    * 审计记录（允许 / 拒绝 计数 + 最近记录内容）。
// ============================================================================

#include "test_util.h"

#include <cstdio>
#include <fstream>
#include <string>

#include "security/access_control.h"

namespace {

const char* const kPolicyText =
    "[default]\n"
    "role = guest\n"
    "[identity]\n"
    "alice = admin\n"
    "eve = user\n"
    "mallory = guest\n"
    "[role:admin]\n"
    "permissions = send_message, send_file, send_image, view_log, manage_users\n"
    "[role:user]\n"
    "permissions = send_message, send_file, send_image\n"
    "[role:guest]\n"
    "permissions = send_message\n";

acl::AccessController makeController() {
    acl::AccessController controller;
    std::string error;
    ST_CHECK(controller.loadText(kPolicyText, error));
    return controller;
}

}  // namespace

// 1. 角色解析
ST_TEST_CASE("access: 身份到角色的映射") {
    const acl::AccessController controller = makeController();
    ST_CHECK_EQ(controller.roleOf("alice"), std::string("admin"));
    ST_CHECK_EQ(controller.roleOf("eve"), std::string("user"));
    ST_CHECK_EQ(controller.roleOf("mallory"), std::string("guest"));
    // 未登记身份 → 默认角色（最小权限）
    ST_CHECK_EQ(controller.roleOf("unregistered"), std::string("guest"));
}

// 2. 判定矩阵
ST_TEST_CASE("access: 允许 / 拒绝判定矩阵") {
    const acl::AccessController controller = makeController();

    // 管理员：全部允许
    ST_CHECK(controller.isAllowed("alice", acl::Operation::kSendMessage));
    ST_CHECK(controller.isAllowed("alice", acl::Operation::kSendFile));
    ST_CHECK(controller.isAllowed("alice", acl::Operation::kSendImage));
    ST_CHECK(controller.isAllowed("alice", acl::Operation::kViewLog));
    ST_CHECK(controller.isAllowed("alice", acl::Operation::kManageUsers));

    // 普通用户：能发消息/文件/图像，不能看日志、不能管用户
    ST_CHECK(controller.isAllowed("eve", acl::Operation::kSendMessage));
    ST_CHECK(controller.isAllowed("eve", acl::Operation::kSendFile));
    ST_CHECK(controller.isAllowed("eve", acl::Operation::kSendImage));
    ST_CHECK(!controller.isAllowed("eve", acl::Operation::kViewLog));
    ST_CHECK(!controller.isAllowed("eve", acl::Operation::kManageUsers));

    // 访客：只能发短消息
    ST_CHECK(controller.isAllowed("mallory", acl::Operation::kSendMessage));
    ST_CHECK(!controller.isAllowed("mallory", acl::Operation::kSendFile));
    ST_CHECK(!controller.isAllowed("mallory", acl::Operation::kSendImage));
    ST_CHECK(!controller.isAllowed("mallory", acl::Operation::kViewLog));

    // 未登记身份 = 访客权限（默认拒绝更严格的操作）
    ST_CHECK(controller.isAllowed("unregistered", acl::Operation::kSendMessage));
    ST_CHECK(!controller.isAllowed("unregistered", acl::Operation::kSendFile));
}

// 3. 权限集合的可读输出
ST_TEST_CASE("access: 权限集合输出") {
    const acl::AccessController controller = makeController();
    const std::string admin = controller.permissionsOf("alice").toString();
    ST_CHECK(admin.find("send_message") != std::string::npos);
    ST_CHECK(admin.find("view_log") != std::string::npos);
    ST_CHECK(admin.find("manage_users") != std::string::npos);

    const std::string guest = controller.permissionsOf("mallory").toString();
    ST_CHECK(guest.find("send_message") != std::string::npos);
    ST_CHECK(guest.find("send_file") == std::string::npos);

    const std::string summary = controller.policySummary();
    ST_CHECK(summary.find("默认角色") != std::string::npos);
    ST_CHECK(summary.find("admin") != std::string::npos);
}

// 4. 非法策略必须被拒绝（默认拒绝原则）
ST_TEST_CASE("access: 非法策略被拒绝") {
    acl::AccessController controller;
    std::string error;

    // 未知权限名
    ST_CHECK(!controller.loadText(
        "[default]\nrole = guest\n[identity]\na = guest\n[role:guest]\n"
        "permissions = send_message, delete_everything\n",
        error));
    ST_CHECK(!error.empty());

    // 默认角色没有定义权限
    ST_CHECK(!controller.loadText(
        "[default]\nrole = guest\n[identity]\na = guest\n[role:user]\n"
        "permissions = send_message\n",
        error));

    // 没有任何身份
    ST_CHECK(!controller.loadText(
        "[default]\nrole = guest\n[role:guest]\npermissions = send_message\n", error));

    // 缺少 '='
    ST_CHECK(!controller.loadText("[identity]\nalice admin\n", error));
}

// 5. 角色未定义权限 → 无权限（最小权限）
ST_TEST_CASE("access: 角色未定义权限时无权限") {
    acl::AccessController controller;
    std::string error;
    ST_CHECK(controller.loadText(
        "[default]\nrole = guest\n[identity]\nalice = ghost\n[role:guest]\n"
        "permissions = send_message\n",
        error));
    // alice 的角色 ghost 没有定义 → 无任何权限
    ST_CHECK(!controller.isAllowed("alice", acl::Operation::kSendMessage));
    ST_CHECK(!controller.isAllowed("alice", acl::Operation::kSendFile));
}

// 6. 消息类型 → 操作 的映射
ST_TEST_CASE("access: 消息类型映射到受保护操作") {
    acl::Operation operation = acl::Operation::kManageUsers;

    ST_CHECK(acl::operationFromMessageType(MessageType::kData, operation));
    ST_CHECK(operation == acl::Operation::kSendMessage);

    ST_CHECK(acl::operationFromMessageType(MessageType::kFileStart, operation));
    ST_CHECK(operation == acl::Operation::kSendFile);
    ST_CHECK(acl::operationFromMessageType(MessageType::kFileChunk, operation));
    ST_CHECK(operation == acl::Operation::kSendFile);
    ST_CHECK(acl::operationFromMessageType(MessageType::kFileEnd, operation));
    ST_CHECK(operation == acl::Operation::kSendFile);

    ST_CHECK(acl::operationFromMessageType(MessageType::kImage, operation));
    ST_CHECK(operation == acl::Operation::kSendImage);

    // 会话控制类消息不属于受保护操作
    ST_CHECK(!acl::operationFromMessageType(MessageType::kClose, operation));
    ST_CHECK(!acl::operationFromMessageType(MessageType::kHello, operation));
    ST_CHECK(!acl::operationFromMessageType(MessageType::kError, operation));
}

// 7. 审计记录
ST_TEST_CASE("access: 审计记录与计数") {
    acl::AccessController controller = makeController();

    controller.record("alice", acl::Operation::kSendFile, true, "test_file_1MB.bin");
    controller.record("mallory", acl::Operation::kSendFile, false, "test_file_1MB.bin");
    controller.record("mallory", acl::Operation::kSendMessage, true, "");

    ST_CHECK_EQ(controller.allowedCount(), 2u);
    ST_CHECK_EQ(controller.deniedCount(), 1u);
    ST_CHECK_EQ(controller.recentDecisions().size(), 3u);

    const std::string& denied = controller.recentDecisions()[1];
    ST_CHECK(denied.find("DENY") != std::string::npos);
    ST_CHECK(denied.find("mallory(guest)") != std::string::npos);
    ST_CHECK(denied.find("send_file") != std::string::npos);

    const std::string& allowed = controller.recentDecisions()[0];
    ST_CHECK(allowed.find("ALLOW") != std::string::npos);
    ST_CHECK(allowed.find("alice(admin)") != std::string::npos);
}

// 8. 审计日志写文件
ST_TEST_CASE("access: 审计日志写入文件") {
    const std::string path = testutil::tempDir() + "/access_test.log";
    (void)std::remove(path.c_str());

    acl::AccessController controller = makeController();
    std::string error;
    ST_CHECK(controller.setAuditLogFile(path, error));
    controller.record("eve", acl::Operation::kViewLog, false, "尝试查看日志");

    std::ifstream in(path);
    ST_CHECK(in.good());
    std::string line;
    std::getline(in, line);
    ST_CHECK(line.find("DENY") != std::string::npos);
    ST_CHECK(line.find("eve(user)") != std::string::npos);
    ST_CHECK(line.find("view_log") != std::string::npos);
}

int main() {
    return ::testutil::runAll("access_control");
}
