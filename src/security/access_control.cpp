// ============================================================================
//  SecureTransfer - 第三部分：访问控制实现
//  file: src/security/access_control.cpp
// ============================================================================

#include "security/access_control.h"

#include <cctype>
#include <ctime>
#include <fstream>
#include <sstream>

#include "common/log.h"

namespace acl {

namespace {

const char* const kLogModule = "AccessControl";

std::string trim(const std::string& text) {
    std::size_t begin = 0;
    std::size_t end = text.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
        --end;
    }
    return text.substr(begin, end - begin);
}

std::string stripComment(const std::string& line) {
    const std::size_t hash = line.find('#');
    const std::size_t semi = line.find(';');
    std::size_t cut = std::string::npos;
    if (hash != std::string::npos) {
        cut = hash;
    }
    if (semi != std::string::npos && (cut == std::string::npos || semi < cut)) {
        cut = semi;
    }
    return cut == std::string::npos ? line : line.substr(0, cut);
}

std::string timestamp() {
    const std::time_t now = std::time(nullptr);
    std::tm local{};
#if defined(_WIN32)
    localtime_s(&local, &now);
#else
    localtime_r(&now, &local);
#endif
    char buffer[32] = {};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local);
    return buffer;
}

}  // namespace

const char* operationToString(Operation operation) {
    switch (operation) {
        case Operation::kSendMessage: return "send_message";
        case Operation::kSendFile: return "send_file";
        case Operation::kSendImage: return "send_image";
        case Operation::kViewLog: return "view_log";
        case Operation::kManageUsers: return "manage_users";
    }
    return "unknown";
}

bool operationFromMessageType(MessageType type, Operation& operation) {
    switch (type) {
        case MessageType::kData:
            operation = Operation::kSendMessage;
            return true;
        case MessageType::kFileStart:
        case MessageType::kFileChunk:
        case MessageType::kFileEnd:
            operation = Operation::kSendFile;
            return true;
        case MessageType::kImage:
            operation = Operation::kSendImage;
            return true;
        default:
            return false;  // kClose / kError 等不需要访问控制
    }
}

void PermissionSet::grant(Operation operation) {
    bits_ |= (1u << static_cast<std::uint32_t>(operation));
}

bool PermissionSet::contains(Operation operation) const {
    return (bits_ & (1u << static_cast<std::uint32_t>(operation))) != 0;
}

std::string PermissionSet::toString() const {
    std::string out;
    const Operation all[] = {Operation::kSendMessage, Operation::kSendFile,
                             Operation::kSendImage, Operation::kViewLog,
                             Operation::kManageUsers};
    for (Operation operation : all) {
        if (contains(operation)) {
            if (!out.empty()) {
                out += ", ";
            }
            out += operationToString(operation);
        }
    }
    return out.empty() ? "(无权限)" : out;
}

bool AccessController::loadText(const std::string& text, std::string& error) {
    Policy policy;
    std::string section;
    std::istringstream stream(text);
    std::string line;

    while (std::getline(stream, line)) {
        const std::string cleaned = trim(stripComment(line));
        if (cleaned.empty()) {
            continue;
        }

        if (cleaned.front() == '[' && cleaned.back() == ']') {
            section = trim(cleaned.substr(1, cleaned.size() - 2));
            continue;
        }

        const std::size_t equals = cleaned.find('=');
        if (equals == std::string::npos) {
            error = "策略配置行格式错误（缺少 '='）: " + cleaned;
            return false;
        }
        const std::string name = trim(cleaned.substr(0, equals));
        const std::string value = trim(cleaned.substr(equals + 1));

        if (section == "default") {
            if (name == "role") {
                policy.defaultRole = value;
            }
        } else if (section == "identity") {
            policy.identityToRole[name] = value;
        } else if (section.rfind("role:", 0) == 0) {
            const std::string role = section.substr(5);
            if (name == "permissions") {
                PermissionSet set;
                std::istringstream items(value);
                std::string item;
                while (std::getline(items, item, ',')) {
                    const std::string token = trim(item);
                    if (token.empty()) {
                        continue;
                    }
                    bool matched = false;
                    const Operation all[] = {
                        Operation::kSendMessage, Operation::kSendFile, Operation::kSendImage,
                        Operation::kViewLog, Operation::kManageUsers};
                    for (Operation operation : all) {
                        if (token == operationToString(operation)) {
                            set.grant(operation);
                            matched = true;
                            break;
                        }
                    }
                    if (!matched) {
                        error = "未知权限名: " + token + "（角色 " + role + "）";
                        return false;
                    }
                }
                policy.rolePermissions[role] = set;
            }
        }
    }

    if (policy.rolePermissions.find(policy.defaultRole) == policy.rolePermissions.end()) {
        error = "默认角色 \"" + policy.defaultRole + "\" 没有定义权限（缺少 [role:" +
                policy.defaultRole + "]）";
        return false;
    }
    if (policy.identityToRole.empty()) {
        error = "策略里没有登记任何身份（缺少 [identity] 段）";
        return false;
    }

    policy_ = policy;
    return true;
}

bool AccessController::loadFile(const std::string& path, std::string& error,
                                std::string& warning) {
    std::ifstream file(path);
    if (!file) {
        error = "无法打开访问控制策略文件: " + path;
        return false;
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    if (!loadText(buffer.str(), error)) {
        error = path + ": " + error;
        return false;
    }

    // 非致命提示：登记了身份，但没有授予任何权限
    for (const auto& entry : policy_.identityToRole) {
        const auto it = policy_.rolePermissions.find(entry.second);
        if (it == policy_.rolePermissions.end()) {
            warning += "身份 " + entry.first + " 的角色 \"" + entry.second +
                       "\" 未定义权限，将按默认拒绝处理；";
        } else if (it->second.empty()) {
            warning += "身份 " + entry.first + " 的角色 \"" + entry.second +
                       "\" 没有任何权限；";
        }
    }
    return true;
}

std::string AccessController::roleOf(const std::string& identity) const {
    const auto it = policy_.identityToRole.find(identity);
    if (it != policy_.identityToRole.end()) {
        return it->second;
    }
    return policy_.defaultRole;  // 未登记身份 → 兜底角色（最小权限）
}

PermissionSet AccessController::permissionsOf(const std::string& identity) const {
    const auto it = policy_.rolePermissions.find(roleOf(identity));
    if (it != policy_.rolePermissions.end()) {
        return it->second;
    }
    return PermissionSet{};  // 角色未定义 → 无权限（默认拒绝）
}

bool AccessController::isAllowed(const std::string& identity, Operation operation) const {
    return permissionsOf(identity).contains(operation);
}

bool AccessController::setAuditLogFile(const std::string& path, std::string& error) {
    if (path.empty()) {
        return true;
    }
    auditFile_.open(path, std::ios::out | std::ios::app);
    if (!auditFile_) {
        error = "无法打开审计日志文件: " + path;
        return false;
    }
    auditPath_ = path;
    return true;
}

void AccessController::record(const std::string& identity,
                              Operation operation,
                              bool allowed,
                              const std::string& detail) {
    const std::string role = roleOf(identity);
    std::ostringstream oss;
    oss << timestamp() << " " << (allowed ? "ALLOW" : "DENY ") << " " << identity << "("
        << role << ") " << operationToString(operation);
    if (!detail.empty()) {
        oss << " " << detail;
    }
    const std::string line = oss.str();

    if (allowed) {
        ++allowedCount_;
    } else {
        ++deniedCount_;
    }
    recent_.push_back(line);
    if (recent_.size() > 200) {  // 只保留最近 200 条供"查看日志"
        recent_.erase(recent_.begin(), recent_.begin() + 100);
    }
    if (auditFile_) {
        auditFile_ << line << std::endl;
        auditFile_.flush();
    }
    if (allowed) {
        ST_LOG_INFO(kLogModule, line);
    } else {
        ST_LOG_WARN(kLogModule, line + "  ← 已拒绝");
    }
}

std::string AccessController::policySummary() const {
    std::ostringstream oss;
    oss << "访问控制策略：\n";
    oss << "  默认角色（未登记身份）: " << policy_.defaultRole << "\n";
    for (const auto& role : policy_.rolePermissions) {
        oss << "  角色 " << role.first << " : " << role.second.toString() << "\n";
    }
    oss << "  身份映射:";
    for (const auto& entry : policy_.identityToRole) {
        oss << " " << entry.first << "→" << entry.second;
    }
    return oss.str();
}

}  // namespace acl
