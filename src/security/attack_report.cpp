// ============================================================================
//  SecureTransfer - 安全层：攻击回执与攻击日志（实现）
//  file: src/security/attack_report.cpp
// ============================================================================

#include "security/attack_report.h"

#include <ctime>
#include <fstream>

#include "common/log.h"
#include "common/path_utils.h"

namespace attack {
namespace {

const char* const kLogModule = "Attack";

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

const char* gateId(RejectGate gate) {
    switch (gate) {
        case RejectGate::kNone:      return "none";
        case RejectGate::kFrame:     return "frame";
        case RejectGate::kFormat:    return "format";
        case RejectGate::kSessionId: return "sessionId";
        case RejectGate::kDirection: return "direction";
        case RejectGate::kType:      return "type";
        case RejectGate::kReplay:    return "replay";
        case RejectGate::kMac:       return "mac";
        case RejectGate::kState:     return "state";
    }
    return "unknown";
}

}  // namespace

bool isAttackReject(RejectGate gate) {
    switch (gate) {
        case RejectGate::kFormat:
        case RejectGate::kSessionId:
        case RejectGate::kDirection:
        case RejectGate::kType:
        case RejectGate::kReplay:
        case RejectGate::kMac:
            return true;
        case RejectGate::kNone:
        case RejectGate::kFrame:
        case RejectGate::kState:
            return false;
    }
    return false;
}

std::string formatAttackReport(RejectGate gate, std::uint64_t sequence, const std::string& reason) {
    return std::string("ATTACK-REPORT: ") + rejectGateToString(gate) +
           " | seq=" + std::to_string(sequence) + " | " + reason;
}

void appendAttackLog(const std::string& path, const std::string& kind, RejectGate gate,
                     const std::string& reason) {
    if (path.empty()) {
        return;
    }
    std::ofstream out = openOutputFile(path, std::ios::out | std::ios::app);
    if (!out) {
        ST_LOG_WARN(kLogModule, "无法写入攻击日志: " + path);
        return;
    }
    out << timestamp() << "  ATTACK  " << kind << "  gate=" << gateId(gate)
        << "  reason=" << reason << "\n";
    out.flush();
}

}  // namespace attack
