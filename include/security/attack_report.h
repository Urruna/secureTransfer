// ============================================================================
//  SecureTransfer - 安全层：攻击回执与攻击日志
//  file: include/security/attack_report.h
//
//  背景：Eve 攻击的判定发生在**受害端进程**里（第七关 CMAC 校验等），
//        攻击端的界面上看不到"我倒在哪一关"。所以受害端在终止前回一条
//        `ATTACK-REPORT: <关卡> | seq=<n> | <原因>`，让攻击端也能显示判定结果。
//
//  这里集中放三样东西，界面（st_ui）与命令行（bob）共用同一份实现，
//  避免格式在两处各写一遍而不一致：
//    1. isAttackReject()      —— 哪些关卡属于"被安全机制拦下"（值得回执）
//    2. formatAttackReport()  —— 回执文本的**唯一**格式定义
//    3. appendAttackLog()     —— 追加一行攻击日志（尽力而为，失败不影响会话）
//
//  说明：这些都不参与加密与完整性保护，只是演示与取证用的应用层约定。
// ============================================================================

#ifndef SECURETRANSFER_SECURITY_ATTACK_REPORT_H
#define SECURETRANSFER_SECURITY_ATTACK_REPORT_H

#include <cstdint>
#include <string>

#include "security/session.h"

namespace attack {

/// 只有"被协议/安全机制拦下"的关卡才值得回执；
/// `kNone`（正常结束）、`kFrame`（socket 断开/超时）、`kState`（状态机错误）
/// 属于非攻击性关闭——回执也发不出去（连接已不可用）。
bool isAttackReject(RejectGate gate);

/// 构造回执文本（攻击端按此前缀识别，见 `common/demo_reply.h` 的自动回复白名单）。
std::string formatAttackReport(RejectGate gate, std::uint64_t sequence, const std::string& reason);

/// 追加一行攻击日志（形如 `2026-10-09 10:20:31  ATTACK  tamper  gate=kMac  reason=…`）。
/// `path` 为空则什么都不做；写失败只记 WARN，不抛异常、不影响会话。
void appendAttackLog(const std::string& path, const std::string& kind, RejectGate gate,
                     const std::string& reason);

}  // namespace attack

#endif  // SECURETRANSFER_SECURITY_ATTACK_REPORT_H
