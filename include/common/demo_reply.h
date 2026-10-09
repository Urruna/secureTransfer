// ============================================================================
//  SecureTransfer - 公共：演示用"自动回复"约定
//  file: include/common/demo_reply.h
//
//  背景（真实踩过的坑）：
//    Alice 与 Bob 为了演示"双向通信"都会对收到的短消息回一条确认。
//    如果双方都对"确认"再回确认，就会无限互相回复（实测中出现过一次
//    三万四千多条消息、12 MB 审计日志的死循环）。
//
//  解决方法（演示约定，与安全协议本身无关）：
//    自动回复统一以 "ACK:" 开头；收到以下"回复型"消息时不再自动回复——
//      ACK: / FILE OK / FILE FAILED / ROLE / AUDIT LOG / ACCESS DENIED /
//      UNKNOWN COMMAND / ATTACK-REPORT / 已收到
//    这样"用户消息 → 确认 → 停止"，不会形成环路。
//
//  注意：这只是**应用层的演示约定**，不参与加密与完整性保护；
//        真实产品通常用请求/响应标识或消息 ID 来配对，而不是字符串前缀。
// ============================================================================

#ifndef SECURETRANSFER_COMMON_DEMO_REPLY_H
#define SECURETRANSFER_COMMON_DEMO_REPLY_H

#include <string>

/// 收到这条明文消息时，是否需要自动回一条确认？(false = 不再回复，避免环路)
inline bool shouldAutoReply(const std::string& text) {
    static const char* const kReplyPrefixes[] = {
        "ACK:",           // 本约定下的自动确认
        "已收到",          // 兼容早期版本的确认文本
        "FILE OK",        // 文件传输确认
        "FILE FAILED",    // 文件传输失败通知
        "ROLE ",          // WHOAMI 的回复
        "AUDIT LOG",      // VIEW_LOG 的回复
        "ACCESS DENIED",  // 访问控制拒绝
        "UNKNOWN COMMAND", // 未知命令回复
        "ATTACK-REPORT"   // 受害端的攻击判定回执（见 security/attack_report.h）
    };
    for (const char* prefix : kReplyPrefixes) {
        if (text.rfind(prefix, 0) == 0) {
            return false;
        }
    }
    return true;
}

#endif  // SECURETRANSFER_COMMON_DEMO_REPLY_H
