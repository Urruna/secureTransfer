// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: src/protocol/transcript.cpp
// ============================================================================

#include "protocol/transcript.h"

namespace transcript {

Bytes tlv(const Bytes& data) {
    Bytes out;
    out.reserve(2 + data.size());
    const std::size_t length = data.size();
    out.push_back(static_cast<Byte>((length >> 8) & 0xFF));
    out.push_back(static_cast<Byte>(length & 0xFF));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

Bytes tlv(const std::string& text) {
    return tlv(stringToBytes(text));
}

Bytes tlv(const Nonce& nonce) {
    return tlv(toBytes(nonce));
}

Bytes tlv(const SessionId& sessionId) {
    return tlv(toBytes(sessionId));
}

namespace {

/// 把若干段拼接起来。
Bytes concat(const Bytes& a, const Bytes& b) {
    Bytes out = a;
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

Bytes concat(const Bytes& a, const Bytes& b, const Bytes& c) {
    return concat(concat(a, b), c);
}

Bytes concat(const Bytes& a, const Bytes& b, const Bytes& c, const Bytes& d) {
    return concat(concat(a, b, c), d);
}

}  // namespace

Bytes authTranscript(const SessionId& sessionId,
                     const std::string& aliceId,
                     const std::string& bobId,
                     const Nonce& nonceA,
                     const Nonce& nonceB) {
    const Bytes header = tlv("ST-AUTH-v1");
    const Bytes sid = tlv(sessionId);
    const Bytes ids = tlv(aliceId);
    const Bytes bid = tlv(bobId);
    const Bytes na = tlv(nonceA);
    const Bytes nb = tlv(nonceB);
    return concat(concat(header, sid, ids, bid), concat(na, nb));
}

Bytes helloAckMacInput(const SessionId& sessionId,
                       const std::string& aliceId,
                       const std::string& bobId,
                       const Nonce& nonceA,
                       const Nonce& nonceB) {
    return concat(authTranscript(sessionId, aliceId, bobId, nonceA, nonceB), tlv("S2C"));
}

Bytes authMacInput(const SessionId& sessionId,
                   const std::string& aliceId,
                   const std::string& bobId,
                   const Nonce& nonceA,
                   const Nonce& nonceB) {
    return concat(authTranscript(sessionId, aliceId, bobId, nonceA, nonceB), tlv("C2S"));
}

Bytes keyRequestMacInput(const SessionId& sessionId,
                         const Nonce& nonceA,
                         const Nonce& nonceB) {
    return concat(concat(tlv("ST-KREQ-v1"), tlv(sessionId), tlv(nonceA), tlv(nonceB)),
                  tlv("C2S"));
}

Bytes keyExchangeMacInput(const SessionId& sessionId,
                          const Nonce& nonceA,
                          const Nonce& nonceB,
                          const Nonce& wrapNonce,
                          const Bytes& wrappedKey) {
    const Bytes head = concat(tlv("ST-KEYEX-v1"), tlv(sessionId), tlv(nonceA), tlv(nonceB));
    return concat(concat(head, tlv(wrapNonce), tlv(wrappedKey)), tlv("S2C"));
}

Bytes keyConfirmMacInput(const SessionId& sessionId,
                         const Nonce& nonceA,
                         const Nonce& nonceB) {
    return concat(concat(tlv("ST-KC-v1"), tlv(sessionId), tlv(nonceA), tlv(nonceB)),
                  tlv("C2S"));
}

Bytes keyConfirmAckMacInput(const SessionId& sessionId,
                            const Nonce& nonceA,
                            const Nonce& nonceB) {
    return concat(concat(tlv("ST-KCA-v1"), tlv(sessionId), tlv(nonceA), tlv(nonceB)),
                  tlv("S2C"));
}

Bytes encKeyDerivationInput() {
    return tlv("ST-DATA-ENC");
}

Bytes macKeyDerivationInput() {
    return tlv("ST-DATA-MAC");
}

}  // namespace transcript
