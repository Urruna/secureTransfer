// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/protocol/transcript.h
//
//  说明：握手阶段的 MAC 输入（转录串）构造。
//
//  为什么需要它：
//    * 握手消息的语义字段（双方 ID、两个 Nonce、包裹后的会话密钥）
//      比数据包头更多，必须显式定义"到底对哪些字节做 MAC"；
//    * 所有字段使用 2 字节长度前缀（TLV）编码，避免"不同字段拼起来
//      字节相同"的歧义攻击；
//    * 每个用途带独立的固定前缀（域分离），避免同一把密钥下不同用途
//      的 MAC 被混用；
//    * 带方向标签（"C2S" / "S2C"），防止把对方的 MAC 反射回来冒充自己。
// ============================================================================

#ifndef SECURETRANSFER_PROTOCOL_TRANSCRIPT_H
#define SECURETRANSFER_PROTOCOL_TRANSCRIPT_H

#include <string>

#include "common/types.h"

namespace transcript {

/// TLV 编码：uint16 大端长度 + 内容。
Bytes tlv(const Bytes& data);
Bytes tlv(const std::string& text);
Bytes tlv(const Nonce& nonce);
Bytes tlv(const SessionId& sessionId);

/// 身份认证的公共转录串：
///   L("ST-AUTH-v1") || L(SessionId) || L(AliceID) || L(BobID) || L(NonceA) || L(NonceB)
Bytes authTranscript(const SessionId& sessionId,
                     const std::string& aliceId,
                     const std::string& bobId,
                     const Nonce& nonceA,
                     const Nonce& nonceB);

/// Bob 的认证标签输入（HELLO_ACK 携带）：authTranscript || L("S2C")
Bytes helloAckMacInput(const SessionId& sessionId,
                       const std::string& aliceId,
                       const std::string& bobId,
                       const Nonce& nonceA,
                       const Nonce& nonceB);

/// Alice 的认证标签输入（AUTH 携带）：authTranscript || L("C2S")
Bytes authMacInput(const SessionId& sessionId,
                   const std::string& aliceId,
                   const std::string& bobId,
                   const Nonce& nonceA,
                   const Nonce& nonceB);

/// KEY_REQUEST 的 MAC 输入。
Bytes keyRequestMacInput(const SessionId& sessionId,
                         const Nonce& nonceA,
                         const Nonce& nonceB);

/// KEY_EXCHANGE 的 MAC 输入（覆盖包裹后的会话密钥与包裹用 Nonce）。
Bytes keyExchangeMacInput(const SessionId& sessionId,
                          const Nonce& nonceA,
                          const Nonce& nonceB,
                          const Nonce& wrapNonce,
                          const Bytes& wrappedKey);

/// KEY_CONFIRM 的 MAC 输入（使用 K_session）。
Bytes keyConfirmMacInput(const SessionId& sessionId,
                         const Nonce& nonceA,
                         const Nonce& nonceB);

/// KEY_CONFIRM_ACK 的 MAC 输入（使用 K_session）。
Bytes keyConfirmAckMacInput(const SessionId& sessionId,
                            const Nonce& nonceA,
                            const Nonce& nonceB);

/// 由 K_session 派生数据加密密钥的输入。
Bytes encKeyDerivationInput();

/// 由 K_session 派生数据 MAC 密钥的输入。
Bytes macKeyDerivationInput();

}  // namespace transcript

#endif  // SECURETRANSFER_PROTOCOL_TRANSCRIPT_H
