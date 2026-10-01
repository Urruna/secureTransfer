// ============================================================================
//  SecureTransfer - 第三部分：访问控制（课程要求 7 的组成部分）
//  file: include/security/access_control.h
//
//  说明：区分两个问题（课程 project_q1.md §6）：
//        身份认证 Authentication  —— 你是谁？（已在第二部分完成）
//        访问控制 Authorization   —— 你可以做什么？（本模块）
//
//  基本流程：
//        身份认证 → 确定身份 → 查角色 Role → 查权限 Permission → 允许 / 拒绝
//
//  设计要点
//    1. **策略与代码分离**：角色、权限、身份到角色的映射全部写在
//       configs/access_policy.conf 里，改策略不需要改代码；
//    2. **默认拒绝**：未知身份落到 defaultRole（默认 guest），
//       而不是"默认允许"；配置缺失时同样按最小权限处理；
//    3. **服务端权威**：真正的判定在服务端（Bob）做，
//       客户端只做本地提示（不信任客户端）；
//    4. **审计留痕**：每次允许 / 拒绝都写一条审计记录（时间、身份、角色、操作、结果），
//       管理员可以查看（对应"管理员可查看日志"的课程示例）。
// ============================================================================

#ifndef SECURETRANSFER_SECURITY_ACCESS_CONTROL_H
#define SECURETRANSFER_SECURITY_ACCESS_CONTROL_H

#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "common/types.h"
#include "protocol/message_type.h"

namespace access {

/// 受保护的操作（应用层能看到的最小动作集合）。
enum class Operation : Byte {
    kSendMessage = 0,  ///< 发送短消息（DATA）
    kSendFile = 1,     ///< 发送文件（FILE_START / CHUNK / END）
    kSendImage = 2,    ///< 发送图像（IMAGE）
    kViewLog = 3,      ///< 查看审计日志（只有管理员）
    kManageUsers = 4   ///< 管理用户 / 角色（只有管理员）
};

const char* operationToString(Operation operation);

/// 从消息类型推断它属于哪种受保护操作。
/// @return 不属于受保护操作时返回 false（例如 kClose / kError）
bool operationFromMessageType(MessageType type, Operation& operation);

/// 权限集合（位图，最多 32 个操作）。
class PermissionSet {
public:
    void grant(Operation operation);
    bool contains(Operation operation) const;
    bool empty() const { return bits_ == 0; }
    std::uint32_t bits() const { return bits_; }
    /// 形如 "send_message, send_file"
    std::string toString() const;

private:
    std::uint32_t bits_ = 0;
};

/// 策略：身份 → 角色 → 权限。
struct Policy {
    std::map<std::string, std::string> identityToRole;     ///< 身份 → 角色名
    std::map<std::string, PermissionSet> rolePermissions;  ///< 角色名 → 权限集合
    std::string defaultRole = "guest";                     ///< 未登记身份的兜底角色
};

/// 访问控制器：加载策略 + 判定 + 审计。
class AccessController {
public:
    /// 从配置文件加载。失败时 error 给出原因；warning 用于非致命提示。
    /// 配置文件格式（INI 风格，`#` / `;` 开头为注释）：
    ///     [default]
    ///     role = guest
    ///     [identity]
    ///     alice = admin
    ///     [role:admin]
    ///     permissions = send_message, send_file, send_image, view_log, manage_users
    bool loadFile(const std::string& path, std::string& error, std::string& warning);

    /// 解析策略文本（便于测试）。
    bool loadText(const std::string& text, std::string& error);

    /// 身份对应的角色名（未登记的身份返回 defaultRole）。
    std::string roleOf(const std::string& identity) const;

    /// 身份拥有的权限集合（未登记的身份返回 defaultRole 的权限）。
    PermissionSet permissionsOf(const std::string& identity) const;

    /// 核心判定：该身份是否允许执行该操作。
    bool isAllowed(const std::string& identity, Operation operation) const;

    /// 设置审计日志文件（追加写入）。路径为空则不写文件，只保留内存记录。
    bool setAuditLogFile(const std::string& path, std::string& error);

    /// 记录一条审计：时间、身份、角色、操作、结果、附加说明。
    void record(const std::string& identity,
                Operation operation,
                bool allowed,
                const std::string& detail);

    /// 最近若干条审计记录（供"查看日志"返回给管理员）。
    const std::vector<std::string>& recentDecisions() const { return recent_; }
    std::size_t allowedCount() const { return allowedCount_; }
    std::size_t deniedCount() const { return deniedCount_; }

    /// 角色与权限的可读总览（用于演示与报告）。
    std::string policySummary() const;

    const Policy& policy() const { return policy_; }

private:
    Policy policy_;
    std::ofstream auditFile_;
    std::string auditPath_;
    std::vector<std::string> recent_;
    std::size_t allowedCount_ = 0;
    std::size_t deniedCount_ = 0;
};

}  // namespace access

#endif  // SECURETRANSFER_SECURITY_ACCESS_CONTROL_H
