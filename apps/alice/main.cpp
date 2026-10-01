// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: apps/alice/main.cpp
//
//  说明：Alice（客户端）。流程：
//        connect → 握手（认证 + 会话密钥分发）→ 发送 4 条课程要求的测试消息
//        → 逐条接收 Bob 的回复并校验 → 发送 CLOSE 结束。
//
//  4 条消息对应课程 project_q1.md §4.4：
//        1 短文本 / 2 普通英文 / 3 长文本+特殊字符 / 4 中文 UTF-8 + 二进制
//
//  用法：
//        ./alice [host] [port] [--key <配置文件>] [--mock] [--placeholder] [--quiet]
//                [--file <路径>]... [--image <路径>]... [--data-dir <目录>]
//                [--id <身份>] [--policy <策略文件>] [--whoami] [--view-log]
//
//        --file / --image：在 4 条文本消息之后，把指定文件 / 图像安全传给 Bob
//                          （可重复；相对路径会去 --data-dir 指定的目录里找，
//                            默认是 experiment_data/）
//        --id      ：覆盖本端身份（演示访问控制时用，例如 --id mallory）
//        --policy  ：加载访问控制策略做**本地提示**（真正的裁决在服务端）
//        --whoami  ：向服务端查询自己的角色与权限
//        --view-log：请求查看服务端审计日志（仅管理员可用）
//  示例：./alice --file test_file_1MB.bin --image test_image_1024x768.png --whoami
// ============================================================================

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "common/hex.h"
#include "common/log.h"
#include "common/types.h"
#include "common/console.h"
#include "application/file_transfer.h"
#include "crypto/aes_crypto_provider.h"
#include "crypto/mac_engine.h"
#include "crypto/mock_crypto_provider.h"
#include "crypto/placeholder_mac_engine.h"
#include "security/keystore.h"
#include "security/access_control.h"
#include "security/session.h"

namespace {

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

std::string describePayload(const Bytes& data) {
    for (Byte b : data) {
        if (b < 0x20 && b != '\t') {
            return "<二进制 " + std::to_string(data.size()) + " 字节>";
        }
    }
    return bytesToString(data);
}

/// 构造第 4 条测试消息：中文 UTF-8 + 一段二进制（模拟文件内容）。
Bytes makeBinaryMessage() {
    const std::string text = "你好，Bob，这是一次安全通信测试。";
    Bytes data = stringToBytes(text);
    for (int i = 0; i < 37; ++i) {
        data.push_back(static_cast<Byte>(i * 7 + 3));
    }
    return data;
}

/// 解析待发送路径：先用原路径，找不到就去 dataDir 里找（方便用 experiment_data/ 里的文件）。
/// 会依次尝试：原路径 → dataDir/文件名 → ../dataDir/文件名，
/// 这样无论从项目根目录还是 build/ 目录运行都能找到实验数据。
std::string resolveDataPath(const std::string& path, const std::string& dataDir) {
    if (path.empty()) {
        return path;
    }
    std::vector<std::string> candidates;
    candidates.push_back(path);
    if (path[0] != '/' && !dataDir.empty()) {
        candidates.push_back(dataDir + "/" + path);
        candidates.push_back("../" + dataDir + "/" + path);
    }
    for (const std::string& candidate : candidates) {
        std::ifstream probe(candidate, std::ios::binary);
        if (probe.good()) {
            return candidate;
        }
    }
    return path;
}

std::string crcHex(std::uint32_t value) {
    static const char* const digits = "0123456789abcdef";
    std::string out = "0x";
    for (int shift = 28; shift >= 0; shift -= 4) {
        out.push_back(digits[(value >> shift) & 0x0F]);
    }
    return out;
}

/// 本地加载访问控制策略（仅用于提示；服务端才是裁决方）。
/// 找不到策略文件时返回 false，但**不影响**程序继续运行。
bool tryLoadPolicyAdvisory(const std::string& explicitPath,
                           acl::AccessController& controller,
                           std::string& usedPath) {
    std::string error;
    std::string warning;
    if (!explicitPath.empty()) {
        if (controller.loadFile(explicitPath, error, warning)) {
            usedPath = explicitPath;
            return true;
        }
        std::cerr << "[WARN] 本地策略加载失败（不影响运行，裁决在服务端）: " << error << std::endl;
        return false;
    }
    const char* const candidates[] = {"configs/access_policy.conf",
                                      "../configs/access_policy.conf",
                                      "/home/securityTransfer/configs/access_policy.conf"};
    for (const char* candidate : candidates) {
        if (controller.loadFile(candidate, error, warning)) {
            usedPath = candidate;
            return true;
        }
    }
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    stconsole::ensureUtf8();
    stlog::initFromEnvironment();

    std::string host = "127.0.0.1";
    std::uint16_t port = 9000;
    std::string keyPath;
    bool useMock = false;
    bool usePlaceholderMac = false;
    bool quiet = false;
    std::vector<std::string> files;
    std::vector<std::string> images;
    std::string dataDir = "experiment_data";
    std::string policyPath;
    std::string identityOverride;
    bool askWhoAmI = false;
    bool askViewLog = false;

    int positional = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--key" && i + 1 < argc) {
            keyPath = argv[++i];
        } else if (arg == "--file" && i + 1 < argc) {
            files.push_back(argv[++i]);
        } else if (arg == "--image" && i + 1 < argc) {
            images.push_back(argv[++i]);
        } else if (arg == "--data-dir" && i + 1 < argc) {
            dataDir = argv[++i];
        } else if (arg == "--id" && i + 1 < argc) {
            identityOverride = argv[++i];
        } else if (arg == "--policy" && i + 1 < argc) {
            policyPath = argv[++i];
        } else if (arg == "--whoami") {
            askWhoAmI = true;
        } else if (arg == "--view-log") {
            askViewLog = true;
        } else if (arg == "--mock") {
            useMock = true;
        } else if (arg == "--placeholder") {
            usePlaceholderMac = true;
        } else if (arg == "--quiet") {
            quiet = true;
        } else if (!arg.empty() && arg[0] != '-') {
            if (positional == 0) {
                host = arg;
            } else if (positional == 1) {
                if (!parsePort(arg, port)) {
                    std::cerr << "[ERROR] 非法端口: " << arg << std::endl;
                    return EXIT_FAILURE;
                }
            }
            ++positional;
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
    config.localId = identityOverride.empty() ? keys.aliceId : identityOverride;
    config.peerId = keys.bobId;
    config.host = host;
    config.port = port;
    config.masterKey = keys.masterKey;
    config.hasMasterKey = true;
    config.logHandshake = !quiet;

    std::cout << "==================== Alice (客户端) ====================" << std::endl;
    std::cout << "目标          : " << host << ":" << port << std::endl;
    std::cout << "身份          : " << config.localId << "（期望对端: " << config.peerId << "）"
              << std::endl;
    std::cout << "K_master 指纹 : " << KeyStore::keyFingerprint(config.masterKey) << std::endl;
    std::cout << "密码算法      : " << crypto.name() << std::endl;
    std::cout << "完整性算法    : " << aesProvider.macEngineName()
              << (crypto.macIsCryptographicallySecure() ? "（密码学强度：达标）"
                                                        : "（⚠ 占位实现，不达标）")
              << std::endl;
    std::cout << "=======================================================" << std::endl;

    // 访问控制：本地只做提示（服务端才是裁决方）
    acl::AccessController accessController;
    std::string policyUsed;
    const bool hasPolicy = tryLoadPolicyAdvisory(policyPath, accessController, policyUsed);
    if (hasPolicy) {
        std::cout << "访问策略(本地提示): " << policyUsed << "  本端角色: "
                  << accessController.roleOf(config.localId) << " ["
                  << accessController.permissionsOf(config.localId).toString() << "]"
                  << std::endl;
        std::cout << "-------------------------------------------------------" << std::endl;
    }

    SecureSession session(crypto, config);
    if (!session.connectToServer()) {
        std::cerr << "[ERROR] [Alice] 握手失败: " << session.lastError() << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "安全会话已建立。SessionId = " << toHex(session.sessionId()) << std::endl;

    std::vector<Bytes> messages;
    messages.push_back(stringToBytes("Hello Bob!"));
    messages.push_back(stringToBytes("A secure message between Alice and Bob."));
    messages.push_back(stringToBytes(
        "Transfer #1024: Alice->Bob, amount=500.00 USD; status=OK! (check: 9f8e7d6c)"));
    messages.push_back(makeBinaryMessage());

    const char* const labels[] = {"测试1 短文本", "测试2 普通英文",
                                  "测试3 长文本+特殊字符", "测试4 中文UTF-8 + 二进制"};

    int failures = 0;
    for (std::size_t i = 0; i < messages.size(); ++i) {
        const Bytes& message = messages[i];
        std::cout << "---------- " << labels[i] << " ----------" << std::endl;
        std::cout << "  发送明文    : " << describePayload(message) << std::endl;
        std::cout << "  明文长度    : " << message.size() << " 字节" << std::endl;

        if (!session.sendMessage(MessageType::kData, message)) {
            std::cerr << "  [ERROR] 发送失败: " << session.lastError() << std::endl;
            ++failures;
            break;
        }
        const PacketTrace& sent = session.lastSentTrace();
        std::cout << "  密文(hex)   : " << toHex(sent.ciphertext) << std::endl;
        std::cout << "  CMAC        : " << toHex(sent.mac) << std::endl;
        std::cout << "  Sequence    : " << sent.sequence << std::endl;
        std::cout << "  Nonce       : " << toHex(sent.nonce) << std::endl;

        MessageType replyType = MessageType::kError;
        Bytes reply;
        if (!session.receiveMessage(replyType, reply)) {
            std::cerr << "  [ERROR] 接收回复失败: " << session.lastError() << std::endl;
            ++failures;
            break;
        }
        std::cout << "  对端回复    : " << describePayload(reply) << std::endl;
        std::cout << "  回复完整性  : MAC 验证通过" << std::endl;
    }

    if (failures == 0) {
        // ---------------- 访问控制命令（可选）----------------
        const auto runCommand = [&](const std::string& command, const char* label) {
            std::cout << "---------- " << label << " ----------" << std::endl;
            if (!session.sendMessage(MessageType::kData, stringToBytes("CMD " + command))) {
                std::cerr << "  [ERROR] 发送命令失败: " << session.lastError() << std::endl;
                ++failures;
                return;
            }
            MessageType replyType = MessageType::kError;
            Bytes reply;
            if (!session.receiveMessage(replyType, reply)) {
                std::cerr << "  [ERROR] 接收命令结果失败: " << session.lastError() << std::endl;
                ++failures;
                return;
            }
            std::cout << "  服务端返回  : " << bytesToString(reply) << std::endl;
        };
        if (askWhoAmI) {
            runCommand("WHOAMI", "查询自己的角色与权限（CMD WHOAMI）");
        }
        if (askViewLog && failures == 0) {
            runCommand("VIEW_LOG", "查看服务端审计日志（CMD VIEW_LOG）");
        }
    }

    if (failures == 0) {
        // ---------------- 文件 / 图像传输（第三部分）----------------
        struct Pending {
            std::string path;
            bool isImage;
        };
        std::vector<Pending> pending;
        for (const std::string& file : files) {
            pending.push_back(Pending{file, false});
        }
        for (const std::string& image : images) {
            pending.push_back(Pending{image, true});
        }

        for (const Pending& item : pending) {
            const std::string path = resolveDataPath(item.path, dataDir);
            const transfer::Kind kind =
                item.isImage ? transfer::Kind::kImage : transfer::Kind::kFile;

            // 本地提示：策略显示没权限时给出预警，但仍然发送（由服务端裁决）
            if (hasPolicy) {
                const acl::Operation operation =
                    item.isImage ? acl::Operation::kSendImage : acl::Operation::kSendFile;
                if (!accessController.isAllowed(config.localId, operation)) {
                    std::cout << "  [本地提示] 角色 " << accessController.roleOf(config.localId)
                              << " 缺少权限 " << acl::operationToString(operation)
                              << "，服务端预计会拒绝" << std::endl;
                }
            }

            std::cout << "---------- " << transfer::kindToString(kind) << "传输: "
                      << path << " ----------" << std::endl;

            const transfer::SendResult sent = transfer::FileSender::send(
                session, path, kind, false,
                [](std::uint64_t done, std::uint64_t total) {
                    if (total >= 1024 * 1024 && (done == total || done % (1024 * 1024) < transfer::kChunkSize)) {
                        std::cout << "    进度: " << (done * 100 / (total ? total : 1)) << "%"
                                  << std::endl;
                    }
                });

            if (!sent.ok) {
                std::cerr << "  [ERROR] " << sent.error << std::endl;
                ++failures;
                break;
            }

            std::cout << "  文件名      : " << sent.fileName << std::endl;
            std::cout << "  大小        : " << sent.bytes << " 字节" << std::endl;
            std::cout << "  传输方式    : "
                      << (sent.singleShot ? "单包（IMAGE，元数据+数据同一包）"
                                          : "分块（FILE_START/CHUNK/END，块大小 " +
                                                std::to_string(transfer::kChunkSize) + " 字节）")
                      << std::endl;
            if (!sent.singleShot) {
                std::cout << "  分块数量    : " << sent.chunks << std::endl;
            }
            std::cout << "  整文件 CRC32: " << crcHex(sent.crc32) << std::endl;
            std::cout << "  发送耗时    : " << std::fixed << std::setprecision(3)
                      << (sent.seconds * 1000.0) << " ms（含加密与网络）" << std::endl;
            std::cout << "  应用层吞吐  : " << std::setprecision(2)
                      << sent.megabytesPerSecond << " MB/s" << std::endl;

            MessageType replyType = MessageType::kError;
            Bytes reply;
            if (!session.receiveMessage(replyType, reply)) {
                std::cerr << "  [ERROR] 等待对端确认失败: " << session.lastError() << std::endl;
                ++failures;
                break;
            }
            std::cout << "  对端确认    : " << describePayload(reply) << std::endl;
        }
    }

    if (failures == 0) {
        if (!session.sendMessage(MessageType::kClose, Bytes{})) {
            std::cerr << "[WARN] 发送 CLOSE 失败: " << session.lastError() << std::endl;
        }
    }

    std::cout << "统计: " << session.stats().summary() << std::endl;
    session.close();

    if (failures != 0) {
        std::cerr << "=== 通信失败: " << failures << " 项 ===" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "=== 4 条测试消息" ;
    if (!files.empty() || !images.empty()) {
        std::cout << " + " << (files.size() + images.size()) << " 个文件/图像";
    }
    std::cout << " 全部安全传输成功 ===" << std::endl;
    return EXIT_SUCCESS;
}
