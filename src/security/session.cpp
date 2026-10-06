// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: src/security/session.cpp
//
//  本文件实现第二部分的全部协议逻辑：
//    1. 握手状态机（HELLO / HELLO_ACK / AUTH / KEY_REQUEST /
//                   KEY_EXCHANGE / KEY_CONFIRM / KEY_CONFIRM_ACK）
//    2. 基于 K_master 的双向身份认证（Challenge-Response + MAC）
//    3. 会话密钥 K_session 的安全分发与双方确认
//    4. 数据阶段的加密（AES-CTR）+ 完整性（MAC）+ 防重放（Sequence）
// ============================================================================

#include "security/session.h"

#include <cstring>
#include <sstream>

#include "common/byte_buffer.h"
#include "common/constant_time.h"
#include "common/hex.h"
#include "common/log.h"
#include "network/frame.h"
#include "protocol/transcript.h"

namespace {

const char* const kLogModule = "Session";
const char* const kHandshakeModule = "Handshake";

/// Nonce 的低 32 位用于消息计数器，因此单个方向最多 2^32-1 条消息。
constexpr std::uint64_t kMaxMessagesPerDirection = 0xFFFFFFFFULL;

/// 课程 project_q1.md 规定的会话密钥（实验测试值）。
/// 真实系统应改为每次会话随机生成：只需要替换这一处。
const Key128 kCourseSessionKey = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

Nonce xorNonces(const Nonce& a, const Nonce& b) {
    Nonce out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<Byte>(a[i] ^ b[i]);
    }
    return out;
}

/// 日志里只打印前几个字节，避免把完整 Nonce 刷屏（Nonce 本身不是密钥）。
std::string shortHex(const Bytes& data, std::size_t maxBytes = 4) {
    const std::size_t length = data.size() < maxBytes ? data.size() : maxBytes;
    std::string out = toHex(data.data(), length);
    if (data.size() > maxBytes) {
        out += "..";
    }
    return out;
}

}  // namespace

const char* sessionStateToString(SessionState state) {
    switch (state) {
        case SessionState::kDisconnected: return "DISCONNECTED";
        case SessionState::kTcpConnected: return "TCP_CONNECTED";
        case SessionState::kAuthenticating: return "AUTHENTICATING";
        case SessionState::kKeyExchange: return "KEY_EXCHANGE";
        case SessionState::kEstablished: return "ESTABLISHED";
        case SessionState::kClosing: return "CLOSING";
        case SessionState::kFailed: return "FAILED";
    }
    return "UNKNOWN";
}

std::string ProtocolStats::summary() const {
    std::ostringstream oss;
    oss << "sent=" << sentPackets << " recv=" << receivedPackets << " bytes=" << sentBytes << "/"
        << receivedBytes << " reject(format/replay/mac/state)=" << rejectedFormat << "/"
        << rejectedReplay << "/" << rejectedMac << "/" << rejectedState
        << " handshake(ok/fail)=" << handshakesOk << "/" << handshakesFailed;
    return oss.str();
}

SecureSession::SecureSession(CryptoProvider& crypto,
                             const SessionConfig& config,
                             RandomSource& random)
    : crypto_(crypto), config_(config), random_(random) {}

SecureSession::~SecureSession() {
    network_.close();
}

// ---------------------------------------------------------------------------
//  方向与 Nonce
// ---------------------------------------------------------------------------

Direction SecureSession::outgoingDirection() const {
    return isServer_ ? Direction::kServerToClient : Direction::kClientToServer;
}

Direction SecureSession::incomingDirection() const {
    return opposite(outgoingDirection());
}

const Bytes& SecureSession::outgoingPrefix() const {
    return isServer_ ? prefixS2C_ : prefixC2S_;
}

Nonce SecureSession::makeNonce(const Bytes& prefix, std::uint64_t counter) const {
    // Nonce = Prefix(8) || 0x00000000(4) || 消息计数器(4, 大端)
    //
    // 为什么计数区只有低 32 位：aes_ctr_xor 会把整个 128 位计数器大端自增，
    // 一条长消息会占用连续多个计数器值。把计数区隔离在低 32 位后，
    // 不同消息的密钥流区间一定不相交（单条消息最多 2^32 个分组）。
    Nonce nonce{};
    for (std::size_t i = 0; i < prefix.size() && i < 8; ++i) {
        nonce[i] = prefix[i];
    }
    nonce[12] = static_cast<Byte>((counter >> 24) & 0xFF);
    nonce[13] = static_cast<Byte>((counter >> 16) & 0xFF);
    nonce[14] = static_cast<Byte>((counter >> 8) & 0xFF);
    nonce[15] = static_cast<Byte>(counter & 0xFF);
    return nonce;
}

// ---------------------------------------------------------------------------
//  出入口
// ---------------------------------------------------------------------------

bool SecureSession::sendWire(const Bytes& wire) {
    if (wire.size() > Frame::kMaxPayloadSize) {
        return fail("数据包超过 Frame 负载上限");
    }
    const Frame frame = Frame::fromBytes(wire);
    if (!network_.sendFrame(frame)) {
        return fail(std::string("发送失败: ") + network_.lastError());
    }
    ++stats_.sentPackets;
    stats_.sentBytes += wire.size() + Frame::kLengthFieldSize;
    lastSentWire_ = wire;
    return true;
}

bool SecureSession::sendRawWireForTesting(const Bytes& wire) {
    if (state_ != SessionState::kEstablished) {
        return fail("会话尚未建立，无法发送原始字节");
    }
    return sendWire(wire);
}

bool SecureSession::recvPacket(Packet& packet, const char* stage) {
    // 握手总时限：单个 recv 有超时，但"对端每次都刚好发一点"可以无限拖时间。
    // 这里再加一道总时限，防止一个客户端长时间占住服务端（慢速握手/资源占用）。
    if (state_ != SessionState::kEstablished && config_.handshakeDeadlineMs > 0) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - handshakeStart_)
                                 .count();
        const long remaining = static_cast<long>(config_.handshakeDeadlineMs) -
                               static_cast<long>(elapsed);
        if (remaining <= 0) {
            return failHandshake("握手总时长超过 " +
                                 std::to_string(config_.handshakeDeadlineMs) +
                                 " ms，已中止（疑似慢速握手占用服务端）");
        }
        // 让"读完当前这一个包"也受剩余时限约束：
        // 否则对端只要每隔几秒发一个字节，就能把服务端一直占住。
        network_.setReadDeadlineMs(static_cast<int>(remaining));
    } else {
        // 数据阶段：按 ioTimeoutMs 走，不设整包期限
        network_.setReadDeadlineMs(0);
    }

    Frame frame;
    if (!network_.receiveFrame(frame)) {
        return fail(std::string(stage) + " 接收失败: " + network_.lastError());
    }
    stats_.receivedBytes += frame.payload.size() + Frame::kLengthFieldSize;

    std::string decodeError;
    if (!Packet::decode(frame.payload, packet, &decodeError)) {
        ++stats_.rejectedFormat;
        return fail(std::string(stage) + " 数据包格式非法: " + decodeError);
    }
    if (sessionIdKnown_ && packet.sessionId != sessionId_) {
        ++stats_.rejectedFormat;
        return fail(std::string(stage) + " SessionId 不属于当前会话");
    }
    if (packet.direction != incomingDirection()) {
        ++stats_.rejectedFormat;
        return fail(std::string(stage) + " 数据包方向不正确（疑似反射攻击）");
    }

    ++stats_.receivedPackets;
    return true;
}

bool SecureSession::sendHandshakePacket(MessageType type, const Nonce& nonce,
                                        const Bytes& body, const MacTag& tag) {
    Packet packet;
    packet.type = type;
    packet.direction = outgoingDirection();
    packet.sessionId = sessionId_;
    packet.sequence = 0;  // 握手包不占用业务序号
    packet.nonce = nonce;
    packet.body = body;
    packet.mac = tag;
    return sendWire(packet.encodeWithMac());
}

// ---------------------------------------------------------------------------
//  握手：客户端（Alice）
// ---------------------------------------------------------------------------

bool SecureSession::handshakeAsClient() {
    state_ = SessionState::kAuthenticating;
    handshakeStart_ = std::chrono::steady_clock::now();  // 握手总时限的起点

    nonceA_ = random_.array<16>();
    sessionId_ = random_.array<8>();
    sessionIdKnown_ = true;

    // ① HELLO：本轮不携带 MAC（Bob 还无法验证 Alice 的身份）
    ByteWriter hello;
    hello.tlv(config_.localId);
    if (!sendHandshakePacket(MessageType::kHello, nonceA_, hello.bytes(), MacTag{})) {
        return false;
    }
    logHandshakeStep("① HELLO 已发送 (SessionId=" + toHex(sessionId_) +
                     ", NonceA=" + shortHex(toBytes(nonceA_)) + ")");

    // ② HELLO_ACK：验证 Bob 的身份
    Packet ack;
    if (!recvPacket(ack, "握手 HELLO_ACK")) {
        return false;
    }
    if (ack.type != MessageType::kHelloAck) {
        return protocolViolation(std::string("期望 HELLO_ACK，收到 ") +
                                 messageTypeToString(ack.type));
    }
    nonceB_ = ack.nonce;

    ByteReader ackReader(ack.body);
    std::string peerId;
    if (!ackReader.tlv(peerId)) {
        return protocolViolation("HELLO_ACK 缺少对端身份字段");
    }
    if (peerId != config_.peerId) {
        return failHandshake("对端自称 \"" + peerId + "\"，与期望身份 \"" +
                             config_.peerId + "\" 不符");
    }

    const MacTag expectedAck = crypto_.cmac(
        config_.masterKey,
        transcript::helloAckMacInput(sessionId_, config_.localId, config_.peerId, nonceA_,
                                     nonceB_));
    if (!constantTimeEquals(expectedAck, ack.mac)) {
        return failHandshake("Authentication Failed：对端未能通过 K_master 认证");
    }
    logHandshakeStep("② HELLO_ACK 验证通过 → Bob 身份认证成功");

    // ③ AUTH：向 Bob 证明自己的身份
    const MacTag tagA = crypto_.cmac(
        config_.masterKey,
        transcript::authMacInput(sessionId_, config_.localId, config_.peerId, nonceA_,
                                 nonceB_));
    if (!sendHandshakePacket(MessageType::kAuth, nonceA_, Bytes{}, tagA)) {
        return false;
    }
    logHandshakeStep("③ AUTH 已发送 → 本端身份已证明");

    // ④ KEY_REQUEST
    state_ = SessionState::kKeyExchange;
    const MacTag tagRequest =
        crypto_.cmac(config_.masterKey,
                     transcript::keyRequestMacInput(sessionId_, nonceA_, nonceB_));
    if (!sendHandshakePacket(MessageType::kKeyRequest, nonceA_, Bytes{}, tagRequest)) {
        return false;
    }
    logHandshakeStep("④ KEY_REQUEST 已发送 → 请求分发会话密钥");

    // ⑤ KEY_EXCHANGE：验证并解包 K_session
    Packet exchange;
    if (!recvPacket(exchange, "握手 KEY_EXCHANGE")) {
        return false;
    }
    if (exchange.type != MessageType::kKeyExchange) {
        return protocolViolation(std::string("期望 KEY_EXCHANGE，收到 ") +
                                 messageTypeToString(exchange.type));
    }
    if (exchange.body.size() != sessionKey_.size()) {
        return protocolViolation("KEY_EXCHANGE 负载长度不是 16 字节");
    }

    const Nonce wrapNonce = xorNonces(nonceA_, nonceB_);
    const MacTag expectedExchange = crypto_.cmac(
        config_.masterKey,
        transcript::keyExchangeMacInput(sessionId_, nonceA_, nonceB_, wrapNonce,
                                        exchange.body));
    if (!constantTimeEquals(expectedExchange, exchange.mac)) {
        return failHandshake("KEY_EXCHANGE 认证失败：包裹的会话密钥被篡改或伪造");
    }

    const Bytes keyStream = crypto_.aesCtrEncrypt(config_.masterKey, wrapNonce,
                                                  Bytes(sessionKey_.size(), 0));
    for (std::size_t i = 0; i < sessionKey_.size(); ++i) {
        sessionKey_[i] = static_cast<Byte>(exchange.body[i] ^ keyStream[i]);
    }
    logHandshakeStep("⑤ KEY_EXCHANGE 验证通过并解包 → 已获得 K_session");

    // ⑥ KEY_CONFIRM：用 K_session 证明自己确实拿到了密钥
    const MacTag confirm =
        crypto_.cmac(sessionKey_,
                     transcript::keyConfirmMacInput(sessionId_, nonceA_, nonceB_));
    if (!sendHandshakePacket(MessageType::kKeyConfirm, nonceA_, Bytes{}, confirm)) {
        return false;
    }
    logHandshakeStep("⑥ KEY_CONFIRM 已发送 → 本端已持有 K_session");

    // ⑦ KEY_CONFIRM_ACK：确认 Bob 也持有同一个 K_session
    Packet confirmAck;
    if (!recvPacket(confirmAck, "握手 KEY_CONFIRM_ACK")) {
        return false;
    }
    if (confirmAck.type != MessageType::kKeyConfirmAck) {
        return protocolViolation(std::string("期望 KEY_CONFIRM_ACK，收到 ") +
                                 messageTypeToString(confirmAck.type));
    }
    const MacTag expectedConfirmAck =
        crypto_.cmac(sessionKey_,
                     transcript::keyConfirmAckMacInput(sessionId_, nonceA_, nonceB_));
    if (!constantTimeEquals(expectedConfirmAck, confirmAck.mac)) {
        return failHandshake("KEY_CONFIRM_ACK 验证失败：双方的 K_session 不一致");
    }
    logHandshakeStep("⑦ KEY_CONFIRM_ACK 验证通过 → 双方持有同一个 K_session");
    return true;
}

// ---------------------------------------------------------------------------
//  握手：服务端（Bob）
// ---------------------------------------------------------------------------

bool SecureSession::handshakeAsServer() {
    state_ = SessionState::kAuthenticating;
    handshakeStart_ = std::chrono::steady_clock::now();  // 握手总时限的起点

    // ① HELLO：学习 SessionId / Alice_ID / Nonce_A
    Packet hello;
    if (!recvPacket(hello, "握手 HELLO")) {
        return false;
    }
    if (hello.type != MessageType::kHello) {
        return protocolViolation(std::string("期望 HELLO，收到 ") +
                                 messageTypeToString(hello.type));
    }
    sessionId_ = hello.sessionId;
    sessionIdKnown_ = true;
    nonceA_ = hello.nonce;

    ByteReader helloReader(hello.body);
    std::string aliceId;
    if (!helloReader.tlv(aliceId)) {
        return protocolViolation("HELLO 缺少发起方身份字段");
    }
    if (aliceId != config_.peerId) {
        return failHandshake("发起方自称 \"" + aliceId + "\"，与期望身份 \"" +
                             config_.peerId + "\" 不符");
    }
    logHandshakeStep("① HELLO 收到 (SessionId=" + toHex(sessionId_) + ", Alice_ID=" +
                     aliceId + ", NonceA=" + shortHex(toBytes(nonceA_)) + ")");

    // ② HELLO_ACK：证明 Bob 的身份
    nonceB_ = random_.array<16>();
    ByteWriter ackBody;
    ackBody.tlv(config_.localId);
    const MacTag tagAck = crypto_.cmac(
        config_.masterKey,
        transcript::helloAckMacInput(sessionId_, aliceId, config_.localId, nonceA_,
                                     nonceB_));
    if (!sendHandshakePacket(MessageType::kHelloAck, nonceB_, ackBody.bytes(), tagAck)) {
        return false;
    }
    logHandshakeStep("② HELLO_ACK 已发送 (NonceB=" + shortHex(toBytes(nonceB_)) + ")");

    // ③ AUTH：验证 Alice 的身份
    Packet auth;
    if (!recvPacket(auth, "握手 AUTH")) {
        return false;
    }
    if (auth.type != MessageType::kAuth) {
        return protocolViolation(std::string("期望 AUTH，收到 ") +
                                 messageTypeToString(auth.type));
    }
    const MacTag expectedAuth = crypto_.cmac(
        config_.masterKey,
        transcript::authMacInput(sessionId_, aliceId, config_.localId, nonceA_, nonceB_));
    if (!constantTimeEquals(expectedAuth, auth.mac)) {
        return failHandshake("Authentication Failed：对端未能通过 K_master 认证");
    }
    logHandshakeStep("③ AUTH 验证通过 → Alice 身份认证成功（双向认证完成）");

    // ④ KEY_REQUEST
    state_ = SessionState::kKeyExchange;
    Packet request;
    if (!recvPacket(request, "握手 KEY_REQUEST")) {
        return false;
    }
    if (request.type != MessageType::kKeyRequest) {
        return protocolViolation(std::string("期望 KEY_REQUEST，收到 ") +
                                 messageTypeToString(request.type));
    }
    const MacTag expectedRequest =
        crypto_.cmac(config_.masterKey,
                     transcript::keyRequestMacInput(sessionId_, nonceA_, nonceB_));
    if (!constantTimeEquals(expectedRequest, request.mac)) {
        return failHandshake("KEY_REQUEST 认证失败");
    }

    // ⑤ KEY_EXCHANGE：包裹并发送 K_session
    //    课程要求会话密钥为固定值，因此必须"真的分发"而不是本地推导。
    sessionKey_ = kCourseSessionKey;
    const Nonce wrapNonce = xorNonces(nonceA_, nonceB_);
    const Bytes keyStream = crypto_.aesCtrEncrypt(config_.masterKey, wrapNonce,
                                                  Bytes(sessionKey_.size(), 0));
    Bytes wrapped(sessionKey_.size());
    for (std::size_t i = 0; i < sessionKey_.size(); ++i) {
        wrapped[i] = static_cast<Byte>(sessionKey_[i] ^ keyStream[i]);
    }
    const MacTag tagExchange = crypto_.cmac(
        config_.masterKey,
        transcript::keyExchangeMacInput(sessionId_, nonceA_, nonceB_, wrapNonce, wrapped));
    if (!sendHandshakePacket(MessageType::kKeyExchange, nonceB_, wrapped, tagExchange)) {
        return false;
    }
    logHandshakeStep("④⑤ KEY_REQUEST 验证通过，KEY_EXCHANGE 已发送 → K_session 已包裹分发");

    // ⑥ KEY_CONFIRM：验证 Alice 也持有 K_session
    Packet confirm;
    if (!recvPacket(confirm, "握手 KEY_CONFIRM")) {
        return false;
    }
    if (confirm.type != MessageType::kKeyConfirm) {
        return protocolViolation(std::string("期望 KEY_CONFIRM，收到 ") +
                                 messageTypeToString(confirm.type));
    }
    const MacTag expectedConfirm =
        crypto_.cmac(sessionKey_,
                     transcript::keyConfirmMacInput(sessionId_, nonceA_, nonceB_));
    if (!constantTimeEquals(expectedConfirm, confirm.mac)) {
        return failHandshake("KEY_CONFIRM 验证失败：对端未持有同一个 K_session");
    }
    logHandshakeStep("⑥ KEY_CONFIRM 验证通过 → 双方持有同一个 K_session");

    // ⑦ KEY_CONFIRM_ACK：反向确认
    const MacTag confirmAck =
        crypto_.cmac(sessionKey_,
                     transcript::keyConfirmAckMacInput(sessionId_, nonceA_, nonceB_));
    if (!sendHandshakePacket(MessageType::kKeyConfirmAck, nonceB_, Bytes{}, confirmAck)) {
        return false;
    }
    logHandshakeStep("⑦ KEY_CONFIRM_ACK 已发送 → 安全会话建立完成");
    return true;
}

// ---------------------------------------------------------------------------
//  会话建立
// ---------------------------------------------------------------------------

bool SecureSession::deriveSessionKeys() {
    // 由 K_session 派生用途分离的子密钥（enc / mac）。
    encKey_ = crypto_.cmac(sessionKey_, transcript::encKeyDerivationInput());
    macKey_ = crypto_.cmac(sessionKey_, transcript::macKeyDerivationInput());

    // 每个方向独立的 Nonce 前缀，保证不同会话、不同方向的密钥流不重复。
    prefixC2S_ = random_.bytes(8);
    prefixS2C_ = random_.bytes(8);

    sendSequence_ = 0;
    replayGuard_.reset();
    state_ = SessionState::kEstablished;
    ++stats_.handshakesOk;
    return true;
}

bool SecureSession::connectToServer() {
    isServer_ = false;
    if (!config_.hasMasterKey) {
        return fail("尚未加载 K_master，无法进行身份认证");
    }
    if (config_.localId.empty() || config_.peerId.empty()) {
        return fail("localId / peerId 不能为空");
    }

    if (!network_.connect(config_.host, config_.port)) {
        state_ = SessionState::kFailed;
        return fail("连接 " + config_.host + ":" + std::to_string(config_.port) +
                    " 失败: " + network_.lastError());
    }
    state_ = SessionState::kTcpConnected;
    network_.setReceiveTimeoutMs(config_.handshakeTimeoutMs);

    if (!handshakeAsClient()) {
        ++stats_.handshakesFailed;
        network_.close();
        state_ = SessionState::kFailed;
        return false;
    }
    if (!deriveSessionKeys()) {
        state_ = SessionState::kFailed;
        return false;
    }
    network_.setReceiveTimeoutMs(config_.ioTimeoutMs);
    return true;
}

bool SecureSession::acceptOneClient(int clientWaitMs) {
    acceptTimedOut_ = false;
    isServer_ = true;
    if (!config_.hasMasterKey) {
        return fail("尚未加载 K_master，无法进行身份认证");
    }
    if (config_.localId.empty() || config_.peerId.empty()) {
        return fail("localId / peerId 不能为空");
    }

    // 注意：允许重复调用（界面用"分片等待 + 重试"实现可取消的 accept），
    // 因此第二次进来时不要重复 listen（同一端口再次 bind 会失败）。
    if (!network_.isListening()) {
        if (!network_.listen(config_.port)) {
            state_ = SessionState::kFailed;
            return fail("监听端口 " + std::to_string(config_.port) + " 失败: " +
                        network_.lastError());
        }
        if (config_.onListening) {
            config_.onListening(network_.boundPort());
        }
    }

    if (clientWaitMs < 0) {
        // 不限时等待（命令行 Bob）：行为与旧版完全一致
        if (!network_.accept()) {
            state_ = SessionState::kFailed;
            return fail(std::string("accept() 失败: ") + network_.lastError());
        }
    } else {
        // 分片等待：先探测监听 socket 是否可读，超时就返回（监听仍然有效，可重试）
        const Network::WaitResult wait = network_.waitAcceptable(clientWaitMs);
        if (wait == Network::WaitResult::kTimeout) {
            acceptTimedOut_ = true;
            lastError_ = "等待客户端连接超时";
            return false;  // 不是失败：state_ 保持未握手状态，监听 socket 继续可用
        }
        if (wait == Network::WaitResult::kError) {
            state_ = SessionState::kFailed;
            return fail(std::string("等待客户端连接失败: ") + network_.lastError());
        }
        if (!network_.accept()) {
            state_ = SessionState::kFailed;
            return fail(std::string("accept() 失败: ") + network_.lastError());
        }
    }
    state_ = SessionState::kTcpConnected;
    network_.setReceiveTimeoutMs(config_.handshakeTimeoutMs);

    if (!handshakeAsServer()) {
        ++stats_.handshakesFailed;
        // 常驻服务：只断开这个客户端，**保留监听 socket**，让下一个客户端还能连进来
        network_.closeConnection();
        sessionIdKnown_ = false;
        state_ = SessionState::kDisconnected;
        return false;
    }
    if (!deriveSessionKeys()) {
        state_ = SessionState::kFailed;
        return false;
    }
    network_.setReceiveTimeoutMs(config_.ioTimeoutMs);
    return true;
}

// ---------------------------------------------------------------------------
//  数据阶段
// ---------------------------------------------------------------------------

bool SecureSession::sendMessage(MessageType type, const Bytes& plaintext) {
    if (state_ != SessionState::kEstablished) {
        ++stats_.rejectedState;
        return fail(std::string("会话尚未建立，不能发送业务数据（当前状态: ") +
                    sessionStateToString(state_) + "）");
    }
    if (!isDataBearing(type)) {
        ++stats_.rejectedState;
        return fail(std::string("消息类型 ") + messageTypeToString(type) +
                    " 不允许携带业务数据");
    }
    if (plaintext.size() > Packet::kMaxBodySize) {
        return fail("消息过长，超过单个数据包允许的最大长度");
    }
    if (sendSequence_ >= kMaxMessagesPerDirection) {
        return fail("本方向消息数已达上限，需要重新建立会话");
    }

    Packet packet;
    packet.type = type;
    packet.direction = outgoingDirection();
    packet.sessionId = sessionId_;
    packet.sequence = sendSequence_ + 1;
    packet.nonce = makeNonce(outgoingPrefix(), packet.sequence);
    // Encrypt-then-MAC：先加密，再对「头部 + 密文」计算 MAC。
    packet.body = crypto_.aesCtrEncrypt(encKey_, packet.nonce, plaintext);
    packet.mac = crypto_.cmac(macKey_, packet.encode());

    lastSentTrace_.valid = true;
    lastSentTrace_.type = packet.type;
    lastSentTrace_.sequence = packet.sequence;
    lastSentTrace_.nonce = packet.nonce;
    lastSentTrace_.ciphertext = packet.body;
    lastSentTrace_.mac = packet.mac;

    if (!sendWire(packet.encodeWithMac())) {
        return false;
    }
    sendSequence_ = packet.sequence;
    return true;
}

bool SecureSession::receiveMessage(MessageType& type, Bytes& plaintext) {
    if (state_ != SessionState::kEstablished) {
        ++stats_.rejectedState;
        return fail(std::string("会话尚未建立，不能接收业务数据（当前状态: ") +
                    sessionStateToString(state_) + "）");
    }

    Packet packet;
    if (!recvPacket(packet, "业务数据")) {
        return false;
    }
    if (!isDataBearing(packet.type)) {
        ++stats_.rejectedState;
        return protocolViolation(std::string("会话已建立，但仍收到非业务数据包: ") +
                                 messageTypeToString(packet.type));
    }

    // 先做便宜的检查（重放），再做贵的检查（MAC）。
    // wouldAccept() 只判断、不推进水位：伪造的大序号包不会影响后续合法包。
    std::string replayReason;
    if (!replayGuard_.wouldAccept(packet.sequence, &replayReason)) {
        ++stats_.rejectedReplay;
        ST_LOG_ERROR(kLogModule,
                     std::string("Replay Attack Detected - Packet rejected: ") + replayReason);
        return fail("Replay Attack Detected: " + replayReason);
    }
    if (!crypto_.verifyCmac(macKey_, packet.encode(), packet.mac)) {
        ++stats_.rejectedMac;
        ST_LOG_ERROR(kLogModule,
                     "CMAC verification failed - Message rejected（数据可能在传输中被篡改）");
        return fail("CMAC verification failed: 数据包完整性校验未通过，已拒绝该消息");
    }
    replayGuard_.commit(packet.sequence);

    lastReceivedTrace_.valid = true;
    lastReceivedTrace_.type = packet.type;
    lastReceivedTrace_.sequence = packet.sequence;
    lastReceivedTrace_.nonce = packet.nonce;
    lastReceivedTrace_.ciphertext = packet.body;
    lastReceivedTrace_.mac = packet.mac;

    type = packet.type;
    plaintext = crypto_.aesCtrDecrypt(encKey_, packet.nonce, packet.body);
    return true;
}

SecureSession::ReceiveStatus SecureSession::tryReceiveMessage(MessageType& type, Bytes& plaintext,
                                                             int waitMs) {
    if (state_ != SessionState::kEstablished) {
        ++stats_.rejectedState;
        (void)fail(std::string("会话尚未建立，不能接收业务数据（当前状态: ") +
                   sessionStateToString(state_) + "）");
        return ReceiveStatus::kClosed;
    }

    // 先探测"有没有数据可读"：数据一到就立刻返回，不再依赖接收超时。
    switch (network_.waitReadable(waitMs)) {
        case Network::WaitResult::kTimeout:
            return ReceiveStatus::kNothing;  // 只是暂时没有数据，不是错误
        case Network::WaitResult::kError:
            (void)fail(std::string("等待对端数据失败: ") + network_.lastError());
            return ReceiveStatus::kClosed;
        case Network::WaitResult::kReadable:
            break;
    }

    // 可读之后走与 receiveMessage() 完全相同的处理路径：
    // 完整性校验、防重放、解密都只有这一处实现，不重复。
    return receiveMessage(type, plaintext) ? ReceiveStatus::kMessage : ReceiveStatus::kClosed;
}

void SecureSession::close() {
    network_.close();
    if (state_ != SessionState::kFailed) {
        state_ = SessionState::kDisconnected;
    }
}

void SecureSession::closeConnection() {
    network_.closeConnection();
    if (state_ != SessionState::kFailed) {
        state_ = SessionState::kDisconnected;
    }
    // 清掉"本次会话"的状态，避免下一个客户端复用旧的 SessionId / 序号
    sessionIdKnown_ = false;
    replayGuard_.reset();
    sendSequence_ = 0;
}

// ---------------------------------------------------------------------------
//  错误处理
// ---------------------------------------------------------------------------

bool SecureSession::fail(const std::string& reason) {
    lastError_ = reason;
    ST_LOG_ERROR(kLogModule, reason);
    return false;
}

bool SecureSession::failHandshake(const std::string& reason) {
    lastError_ = reason;
    ST_LOG_ERROR(kHandshakeModule, reason);
    return false;
}

bool SecureSession::protocolViolation(const std::string& reason) {
    ++stats_.rejectedState;
    return fail("协议违规: " + reason);
}

void SecureSession::logHandshakeStep(const std::string& message) const {
    if (config_.logHandshake) {
        ST_LOG_INFO(kHandshakeModule, message);
    }
}
