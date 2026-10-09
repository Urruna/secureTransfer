// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: apps/bob/main.cpp
//
//  说明：Bob（服务端）。流程：
//        listen/accept → 握手（认证 + 会话密钥分发）→ 逐条接收加密消息
//        → 每条回复一个确认消息 → 收到 CLOSE 后结束并打印统计。
//
//  用法：
//        ./bob [port] [--key <配置文件>] [--mock] [--placeholder] [--quiet]
//              [--out-dir <目录>] [--id <本端身份>] [--peer <对端身份>]
//              [--policy <策略文件>] [--access-log <日志文件>]
//
//        --out-dir：接收到的文件 / 图像保存目录（默认 experiment_data/received）
//        --peer  ：本次会话接受的**对端身份**（握手时会校验，防止冒充；
//                  演示访问控制时可用它切换成 eve / mallory 等身份）
//        --once  ：只服务一个客户端就退出（脚本 / 测试用；失败也退出）
//
//  默认是**常驻服务**：可以连续服务多个客户端，Ctrl+C 结束；
//  单个客户端握手失败不会再让服务退出（带连续失败退避），
//  整次握手还有总时长上限（SessionConfig::handshakeDeadlineMs），防止慢速握手占用服务端。
//
//        默认 port = 9000，密钥文件按 configs/keys.conf 等候选路径查找。
// ============================================================================

#include <cstdlib>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "application/file_transfer.h"
#include "common/path_utils.h"
#include "common/text_encoding.h"
#include "security/access_control.h"
#include "security/attack_report.h"
#include "common/hex.h"
#include "common/log.h"
#include "common/console.h"
#include "common/demo_reply.h"
#include "common/types.h"
#include "crypto/aes_crypto_provider.h"
#include "crypto/mac_engine.h"
#include "crypto/mock_crypto_provider.h"
#include "crypto/placeholder_mac_engine.h"
#include "security/keystore.h"
#include "security/session.h"

namespace {

/// 按候选路径查找密钥配置文件。
bool loadKeyStore(const std::string& explicitPath, KeyStoreConfig& out) {
    std::string error;
    std::string warning;
    if (!explicitPath.empty()) {
        if (!KeyStore::loadFile(explicitPath, out, error, warning)) {
            std::cerr << "[ERROR] " << error << std::endl;
            return false;
        }
        if (!warning.empty()) {
            std::cerr << "[WARN] " << warning << std::endl;
        }
        return true;
    }

    const char* const candidates[] = {"configs/keys.conf", "../configs/keys.conf",
                                      "/home/securityTransfer/configs/keys.conf"};
    for (const char* candidate : candidates) {
        if (KeyStore::loadFile(candidate, out, error, warning)) {
            if (!warning.empty()) {
                std::cerr << "[WARN] " << warning << std::endl;
            }
            return true;
        }
    }
    std::cerr << "[ERROR] 找不到密钥配置文件，请用 --key <路径> 指定" << std::endl;
    return false;
}

bool parsePort(const std::string& text, std::uint16_t& port) {
    try {
        const unsigned long value = std::stoul(text);
        if (value == 0 || value > 65535) {
            return false;
        }
        port = static_cast<std::uint16_t>(value);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

/// 尽量把消息按 UTF-8 文本显示；含控制字符时只显示十六进制。
std::string describePayload(const Bytes& data) {
    for (Byte b : data) {
        if (b < 0x20 && b != '\t') {
            return "<二进制 " + std::to_string(data.size()) + " 字节> " +
                   toHex(data.data(), data.size() < 32 ? data.size() : 32);
        }
    }
    return bytesToString(data);
}

std::string crcHex(std::uint32_t value) {
    static const char* const digits = "0123456789abcdef";
    std::string out = "0x";
    for (int shift = 28; shift >= 0; shift -= 4) {
        out.push_back(digits[(value >> shift) & 0x0F]);
    }
    return out;
}

/// 在若干候选路径中查找访问控制策略文件。
bool loadPolicy(const std::string& explicitPath, acl::AccessController& controller,
                std::string& usedPath) {
    std::string error;
    std::string warning;
    if (!explicitPath.empty()) {
        if (!controller.loadFile(explicitPath, error, warning)) {
            std::cerr << "[ERROR] " << error << std::endl;
            return false;
        }
        usedPath = explicitPath;
        if (!warning.empty()) {
            std::cerr << "[WARN] " << warning << std::endl;
        }
        return true;
    }
    const char* const candidates[] = {"configs/access_policy.conf",
                                      "../configs/access_policy.conf",
                                      "/home/securityTransfer/configs/access_policy.conf"};
    for (const char* candidate : candidates) {
        if (controller.loadFile(candidate, error, warning)) {
            usedPath = candidate;
            if (!warning.empty()) {
                std::cerr << "[WARN] " << warning << std::endl;
            }
            return true;
        }
    }
    std::cerr << "[ERROR] 找不到访问控制策略文件，请用 --policy <路径> 指定" << std::endl;
    return false;
}

/// 解析命令：正文以 "CMD " 开头时视为应用层命令。
bool parseCommand(const Bytes& body, std::string& command) {
    const std::string text = bytesToString(body);
    if (text.rfind("CMD ", 0) != 0) {
        return false;
    }
    command = text.substr(4);
    return true;
}

/// 常驻服务的停止标志：Ctrl+C / SIGTERM 只置位，主循环里安全退出。
std::atomic<bool> g_stopRequested{false};

void handleStopSignal(int) {
    g_stopRequested.store(true);
}

/// 命令行帮助（--help）。默认是常驻服务，可以连续服务多个客户端。
void printUsage() {
    std::cout << R"(用法：./bob [端口] [选项]

  端口                     监听端口（默认 9000）
  --key <文件>             密钥配置（默认 configs/keys.conf）
  --policy <文件>          访问控制策略
  --access-log <文件>      审计日志
  --out-dir <目录>         接收文件 / 图像的保存目录
  --id <身份>              本端身份（默认 bob）
  --peer <身份>            期望的对端身份（默认 alice）
  --quiet                  减少输出
  --once                   只服务一个客户端就退出（脚本 / 测试用）
  --max-sessions <N>       服务 N 次会话后退出（0 = 不限）
  --mock / --placeholder   演示用：换成占位算法（不具备密码学强度）
  --help                   显示本帮助

默认行为：**常驻服务**，可连续服务多个客户端，Ctrl+C 结束。
默认端口是 9000。
)";
}

}  // namespace

namespace {

/// 处理一次**已经握手完成**的会话。
/// 返回 true  = 对端正常发送 CLOSE，会话正常结束；
/// 返回 false = 本次会话出错（常驻服务可以继续服务下一个客户端）。
bool serveOneSession(SecureSession& session,
                     acl::AccessController& accessController,
                     const SessionConfig& config,
                     const std::string& outDir,
                     const std::string& attackLogPath) {
    std::cout << "安全会话已建立。SessionId = " << toHex(session.sessionId()) << std::endl;
    std::cout << "NonceA = " << toHex(session.nonceA()) << std::endl;
    std::cout << "NonceB = " << toHex(session.nonceB()) << std::endl;

    int received = 0;
    int transfers = 0;
    int denials = 0;
    bool droppingTransfer = false;  // 被拒绝的传输：只丢弃后续数据块，不落盘
    transfer::TransferReceiver receiver(outDir);
    for (;;) {
        MessageType type = MessageType::kError;
        Bytes plaintext;
        if (!session.receiveMessage(type, plaintext)) {
            std::cerr << "[ERROR] [Bob] 接收失败: " << session.lastError() << std::endl;
            // 被安全机制拦下（篡改/重放/伪造…）时，关闭前给对端回一条判定结果，
            // 并把这次攻击写进独立的攻击日志（与 UI 侧共用 security/attack_report.h）。
            const RejectGate gate = session.lastRejectGate();
            if (attack::isAttackReject(gate) && session.state() == SessionState::kEstablished) {
                const std::string report = attack::formatAttackReport(
                    gate, session.receiveSequence(), session.lastError());
                if (!session.sendMessage(MessageType::kData, stringToBytes(report))) {
                    std::cout << "（ATTACK-REPORT 发送失败：对端可能已关闭）" << std::endl;
                } else {
                    std::cout << "已向对端回执：" << report << std::endl;
                }
                attack::appendAttackLog(attackLogPath, "cli", gate, session.lastError());
            }
            session.close();
            std::cout << "统计: " << session.stats().summary() << std::endl;
            return false;
        }

        if (type == MessageType::kClose) {
            std::cout << "收到对端 CLOSE 消息，会话正常结束。" << std::endl;
            break;
        }

        // ---------------- 访问控制：先判定，再执行 ----------------
        // 身份取自**握手时认证过的对端标识**（config.peerId），不是客户端自称
        acl::Operation operation = acl::Operation::kSendMessage;
        const bool protectedOperation = acl::operationFromMessageType(type, operation);

        // 被拒绝的传输只剩数据块与结束包，静默丢弃（保证不落盘）
        if (droppingTransfer &&
            (type == MessageType::kFileChunk || type == MessageType::kFileEnd)) {
            if (type == MessageType::kFileEnd) {
                droppingTransfer = false;
                std::cout << "（被拒绝的传输已丢弃完毕）" << std::endl;
            }
            continue;
        }
        if (type == MessageType::kFileStart || type == MessageType::kImage) {
            droppingTransfer = false;
        }

        if (protectedOperation && !accessController.isAllowed(config.peerId, operation)) {
            ++denials;
            accessController.record(config.peerId, operation, false, "服务端判定无权限");
            std::cout << "【访问控制拒绝】身份 " << config.peerId << "（角色 "
                      << accessController.roleOf(config.peerId) << "）尝试 "
                      << acl::operationToString(operation) << " —— 已拒绝，未执行" << std::endl;
            if (type == MessageType::kFileStart || type == MessageType::kImage) {
                droppingTransfer = true;
            }
            (void)session.sendMessage(
                MessageType::kData,
                stringToBytes(std::string("ACCESS DENIED: ") +
                              acl::operationToString(operation) + " 需要更高权限（当前角色 " +
                              accessController.roleOf(config.peerId) + "）"));
            continue;  // 会话保持可用（与篡改/重放导致断连不同）
        }
        if (protectedOperation) {
            accessController.record(config.peerId, operation, true, "");
        }

        // ---------------- 应用层命令（CMD ...）----------------
        std::string command;
        if (parseCommand(plaintext, command)) {
            if (command == "WHOAMI") {
                (void)session.sendMessage(
                    MessageType::kData,
                    stringToBytes("ROLE " + accessController.roleOf(config.peerId) + " : " +
                                  accessController.permissionsOf(config.peerId).toString()));
            } else if (command == "VIEW_LOG") {
                if (!accessController.isAllowed(config.peerId, acl::Operation::kViewLog)) {
                    accessController.record(config.peerId, acl::Operation::kViewLog, false,
                                            "尝试查看审计日志");
                    ++denials;
                    std::cout << "【访问控制拒绝】" << config.peerId << " 尝试 view_log" << std::endl;
                    (void)session.sendMessage(
                        MessageType::kData,
                        stringToBytes("ACCESS DENIED: view_log 仅管理员可用（当前角色 " +
                                      accessController.roleOf(config.peerId) + "）"));
                } else {
                    accessController.record(config.peerId, acl::Operation::kViewLog, true, "");
                    const auto& decisions = accessController.recentDecisions();
                    std::string reply = "AUDIT LOG (最近 " + std::to_string(decisions.size()) +
                                        " 条, 允许 " +
                                        std::to_string(accessController.allowedCount()) +
                                        " 次 / 拒绝 " +
                                        std::to_string(accessController.deniedCount()) + " 次)";
                    const std::size_t begin =
                        decisions.size() > 6 ? decisions.size() - 6 : 0;
                    for (std::size_t i = begin; i < decisions.size(); ++i) {
                        reply += "\n" + decisions[i];
                    }
                    (void)session.sendMessage(MessageType::kData, stringToBytes(reply));
                }
            } else {
                (void)session.sendMessage(MessageType::kData,
                                          stringToBytes("UNKNOWN COMMAND: " + command));
            }
            continue;
        }

        // ---------------- 文件 / 图像传输（第三部分）----------------
        std::string transferError;
        const bool wasInProgress = receiver.inProgress();
        if (receiver.handle(type, plaintext, &transferError)) {
            if (!transferError.empty()) {
                std::cerr << "[WARN] [Bob] 传输消息处理异常: " << transferError << std::endl;
                (void)session.sendMessage(
                    MessageType::kData,
                    stringToBytes("FILE FAILED: " + transferError));
                continue;
            }
            if (receiver.inProgress()) {
                const std::uint64_t done = receiver.receivedBytes();
                const std::uint64_t total = receiver.expectedBytes();
                if (!wasInProgress) {
                    std::cout << "---------- 开始接收 " << receiver.currentFileName()
                              << "（" << total << " 字节）----------" << std::endl;
                } else if (total > 0 && done * 4 / total != (done - plaintext.size()) * 4 / total) {
                    std::cout << "    已接收 " << (done * 100 / total) << "%" << std::endl;
                }
                continue;
            }

            const transfer::ReceiveResult& result = receiver.lastResult();
            ++transfers;
            std::cout << "---------- 第 " << transfers << " 个文件/图像接收完成 ----------"
                      << std::endl;
            std::cout << "  文件名      : " << result.fileName << std::endl;
            std::cout << "  类型        : " << transfer::kindToString(result.kind) << std::endl;
            std::cout << "  大小        : " << result.bytes << " 字节" << std::endl;
            std::cout << "  传输方式    : "
                      << (result.singleShot ? "单包（IMAGE）" : "分块") << std::endl;
            if (!result.singleShot) {
                std::cout << "  分块数量    : " << result.chunks << std::endl;
            }
            std::cout << "  整文件 CRC32: " << crcHex(result.crc32) << std::endl;
            std::cout << "  校验结果    : "
                      << (result.ok ? "通过（字节数一致 + CRC32 一致）"
                                    : "失败：" + result.error)
                      << std::endl;
            std::cout << "  保存位置    : " << result.savedPath << std::endl;

            const std::string ack =
                (result.ok ? "FILE OK " : "FILE FAILED ") + result.fileName + " (" +
                std::to_string(result.bytes) + " 字节, CRC32=" + crcHex(result.crc32) + ")";
            if (!session.sendMessage(MessageType::kData, stringToBytes(ack))) {
                std::cerr << "[ERROR] [Bob] 回复失败: " << session.lastError() << std::endl;
                session.close();
                return false;
            }
            continue;
        }

        ++received;
        const PacketTrace& trace = session.lastReceivedTrace();
        std::cout << "---------- 第 " << received << " 条消息 ----------" << std::endl;
        std::cout << "  Type        : " << messageTypeToString(type) << std::endl;
        std::cout << "  Sequence    : " << trace.sequence << std::endl;
        std::cout << "  Nonce       : " << toHex(trace.nonce) << std::endl;
        std::cout << "  密文(hex)   : " << toHex(trace.ciphertext) << std::endl;
        std::cout << "  CMAC        : " << toHex(trace.mac) << std::endl;
        std::cout << "  MAC 验证    : 通过（数据未被篡改）" << std::endl;
        std::cout << "  解密明文    : " << describePayload(plaintext) << std::endl;
        std::cout << "  明文长度    : " << plaintext.size() << " 字节" << std::endl;

        // 自动回复：以 "ACK:" 开头；对"回复型"消息不再回复，避免两端互相回复成死循环
        const std::string text = bytesToString(plaintext);
        if (shouldAutoReply(text)) {
            const std::string ack = "ACK: Bob 已收到第 " + std::to_string(received) + " 条消息（" +
                                    std::to_string(plaintext.size()) + " 字节）";
            if (!session.sendMessage(MessageType::kData, stringToBytes(ack))) {
                std::cerr << "[ERROR] [Bob] 回复失败: " << session.lastError() << std::endl;
                session.close();
                return false;
            }
        } else {
            std::cout << "  （这是对端的回复型消息，不再自动回复）" << std::endl;
        }
    }

    std::cout << "共接收 " << received << " 条加密消息，" << transfers << " 个文件/图像；"
              << "访问控制拒绝 " << denials << " 次（允许 "
              << accessController.allowedCount() << " 次 / 拒绝 "
              << accessController.deniedCount() << " 次）。" << std::endl;
    std::cout << "统计: " << session.stats().summary() << std::endl;
    session.close();
    ST_LOG_INFO("Bob", "安全通信流程结束");
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    stconsole::ensureUtf8();
    stlog::initFromEnvironment();

    // 统一把命令行参数转成 UTF-8：Windows 上 argv 是 ANSI 代码页（GBK），
    // 直接用会让 `--out-dir D:\测试\收到的文件` 这类中文路径失效。
    const std::vector<std::string> args = sttext::utf8CommandLine(argc, argv);

    std::uint16_t port = 9000;
    std::string keyPath;
    bool useMock = false;
    bool usePlaceholderMac = false;
    bool quiet = false;
    std::string outDir = "experiment_data/received";
    std::string policyPath;
    std::string accessLogPath = "experiment_data/access_log.txt";
    std::string identityOverride;
    std::string peerOverride;
    bool serveOnce = false;        // --once：只服务一个客户端就退出（脚本/测试用）
    long maxSessions = 0;          // --max-sessions N：服务 N 次后退出（0 = 不限）

    for (std::size_t i = 1; i < args.size(); ++i) {
        const std::string arg = args[i];
        if (arg == "--key" && i + 1 < args.size()) {
            keyPath = args[++i];
        } else if (arg == "--out-dir" && i + 1 < args.size()) {
            outDir = args[++i];
        } else if (arg == "--policy" && i + 1 < args.size()) {
            policyPath = args[++i];
        } else if (arg == "--access-log" && i + 1 < args.size()) {
            accessLogPath = args[++i];
        } else if (arg == "--id" && i + 1 < args.size()) {
            identityOverride = args[++i];
        } else if (arg == "--peer" && i + 1 < args.size()) {
            peerOverride = args[++i];
        } else if (arg == "--once") {
            serveOnce = true;
        } else if (arg == "--max-sessions" && i + 1 < args.size()) {
            maxSessions = std::strtol(args[++i].c_str(), nullptr, 10);
            if (maxSessions < 0) {
                maxSessions = 0;
            }
        } else if (arg == "--help" || arg == "-h") {
            printUsage();
            return EXIT_SUCCESS;
        } else if (arg == "--mock") {
            useMock = true;
        } else if (arg == "--placeholder") {
            usePlaceholderMac = true;
        } else if (arg == "--quiet") {
            quiet = true;
        } else if (!arg.empty() && arg[0] != '-' && !parsePort(arg, port)) {
            std::cerr << "[ERROR] 非法端口: " << arg << std::endl;
            return EXIT_FAILURE;
        }
    }

    KeyStoreConfig keys;
    if (!loadKeyStore(keyPath, keys)) {
        return EXIT_FAILURE;
    }

    // 默认：真实 AES-CTR + 第一部分的 CMAC（RFC 4493）
    PlaceholderMacEngine placeholderMac;
    AesCryptoProvider aesProvider(usePlaceholderMac ? static_cast<MacEngine*>(&placeholderMac)
                                                   : nullptr);
    MockCryptoProvider mockProvider;
    CryptoProvider& crypto = useMock ? static_cast<CryptoProvider&>(mockProvider)
                                     : static_cast<CryptoProvider&>(aesProvider);

    SessionConfig config;
    config.localId = identityOverride.empty() ? keys.bobId : identityOverride;
    config.peerId = peerOverride.empty() ? keys.aliceId : peerOverride;
    config.port = port;
    config.masterKey = keys.masterKey;
    config.hasMasterKey = true;
    config.logHandshake = !quiet;

    std::cout << "==================== Bob (服务端) ====================" << std::endl;
    std::cout << "身份          : " << config.localId << "（期望对端: " << config.peerId << "）"
              << std::endl;
    std::cout << "K_master 指纹 : " << KeyStore::keyFingerprint(config.masterKey)
              << "（仅指纹，不打印密钥内容）" << std::endl;
    std::cout << "密码算法      : " << crypto.name() << std::endl;
    std::cout << "完整性算法    : " << aesProvider.macEngineName()
              << (crypto.macIsCryptographicallySecure() ? "（密码学强度：达标）"
                                                        : "（⚠ 占位实现，不达标）")
              << std::endl;
    std::cout << "=====================================================" << std::endl;

    // ---------------- 访问控制策略（服务端权威判定）----------------
    acl::AccessController accessController;
    std::string policyUsed;
    if (!loadPolicy(policyPath, accessController, policyUsed)) {
        return EXIT_FAILURE;
    }
    const std::string logDir = accessLogPath.substr(0, accessLogPath.find_last_of('/'));
    if (!logDir.empty() && logDir != accessLogPath) {
        (void)ensureDirectory(logDir);
    }
    // 攻击日志与审计日志同目录（单独一份文件，避免把攻击演示混进访问控制审计）
    const std::string attackLogPath =
        (logDir.empty() || logDir == accessLogPath ? std::string("experiment_data") : logDir) +
        "/attack_log.txt";
    if (!outDir.empty()) {
        (void)ensureDirectory(outDir);
    }
    std::string logError;
    if (!accessController.setAuditLogFile(accessLogPath, logError)) {
        std::cerr << "[WARN] " << logError << "（审计只记录在内存中）" << std::endl;
    }
    std::cout << "访问策略      : " << policyUsed << "（裁决方：服务端）" << std::endl;
    std::cout << "本端角色      : " << accessController.roleOf(config.localId) << " ["
              << accessController.permissionsOf(config.localId).toString() << "]" << std::endl;
    std::cout << "对端角色      : " << accessController.roleOf(config.peerId) << " ["
              << accessController.permissionsOf(config.peerId).toString() << "]" << std::endl;
    std::cout << "审计日志      : " << accessLogPath << std::endl;
    std::cout << "-----------------------------------------------------" << std::endl;

    // Ctrl+C / SIGTERM：只置停止标志，由主循环安全退出（常驻服务需要能优雅结束）
    std::signal(SIGINT, handleStopSignal);
#ifdef SIGTERM
    std::signal(SIGTERM, handleStopSignal);
#endif

    SecureSession session(crypto, config);
    // 一次会话的处理体已搬进 serveOneSession()（见文件上方）；
    // 下面这段循环负责：等待客户端 → 处理本次会话 → 关连接（保留监听）→ 继续等待。
    constexpr int kAcceptSliceMs = 200;  // 分片等待：既能及时响应 Ctrl+C，也不空转
    int servedSessions = 0;
    int failedHandshakes = 0;
    int consecutiveFailures = 0;
    std::cout << "服务模式      : "
              << (serveOnce ? "单次会话（--once）"
                            : "常驻：可连续服务多个客户端（Ctrl+C 结束）")
              << std::endl;
    std::cout << "-----------------------------------------------------" << std::endl;

    while (!g_stopRequested) {
        const auto attemptStart = std::chrono::steady_clock::now();
        if (!session.acceptOneClient(kAcceptSliceMs)) {
            if (session.lastAcceptTimedOut()) {
                continue;  // 这段时间没有客户端接入：继续等
            }
            // 握手失败（对端连上就断、认证失败、握手超时……）不再让服务退出
            ++failedHandshakes;
            ++consecutiveFailures;
            std::cerr << "[WARN] [Bob] 本次连接建立/握手失败（服务继续运行）: "
                      << session.lastError() << "（连续失败 " << consecutiveFailures << " 次）"
                      << std::endl;
            if (serveOnce) {
                return EXIT_FAILURE;  // --once：保持"失败即退出"的旧行为
            }
            // 限流策略："只有真正占用过服务端"的失败才短暂退避。
            // "连上就断"的洪泛几乎不耗时（accept 后立刻读到 EOF），直接继续服务即可；
            // 而"慢速握手"这类会占用服务端的失败（已被总时限掐断）则让它慢下来。
            const auto attemptMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::steady_clock::now() - attemptStart)
                                       .count();
            if (attemptMs >= 500) {
                std::cout << "（本次失败占用了 " << attemptMs << " ms，暂停 200 ms 再继续）"
                          << std::endl;
                for (int slept = 0; slept < 200 && !g_stopRequested; slept += 50) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
            }
            continue;
        }

        consecutiveFailures = 0;
        ++servedSessions;
        if (!serveOneSession(session, accessController, config, outDir, attackLogPath)) {
            std::cerr << "[WARN] [Bob] 本次会话异常结束（服务继续运行）" << std::endl;
        }
        session.closeConnection();  // 只关连接、保留监听，准备服务下一个客户端

        if (serveOnce ||
            (maxSessions > 0 && static_cast<long>(servedSessions) >= maxSessions)) {
            break;
        }
    }

    session.close();
    std::cout << "服务结束：完成会话 " << servedSessions << " 次，握手失败 " << failedHandshakes
              << " 次。" << std::endl;
    ST_LOG_INFO("Bob", "安全通信流程结束");
    return EXIT_SUCCESS;
}
