// ============================================================================
//  SecureTransfer - 第三部分：Qt 图形界面的会话工作线程（实现）
//  file: apps/ui/session_worker.cpp
// ============================================================================

#include "session_worker.h"

#include <QFileInfo>
#include <QStringList>

#include <algorithm>
#include <chrono>
#include <string>

#include "application/file_transfer.h"
#include "common/hex.h"
#include "common/log.h"
#include "common/demo_reply.h"
#include "common/path_utils.h"
#include "crypto/aes_crypto_provider.h"
#include "protocol/packet.h"
#include "security/access_control.h"
#include "security/attack_report.h"
#include "security/keystore.h"
#include "security/session.h"

namespace {

const char* const kLogModule = "SessionWorker";

/// 界面语言：把 C++ 侧的类型名转成中文可读文本。
QString typeToText(MessageType type) {
    switch (type) {
        case MessageType::kData: return "短消息";
        case MessageType::kFileStart: return "文件开始";
        case MessageType::kFileChunk: return "文件数据块";
        case MessageType::kFileEnd: return "文件结束";
        case MessageType::kImage: return "图像";
        case MessageType::kClose: return "会话结束";
        case MessageType::kError: return "错误";
        default: return "其它";
    }
}

QString fromHexBytes(const Bytes& data, std::size_t maxBytes = 8) {
    const std::size_t length = std::min(maxBytes, data.size());
    QString out = QString::fromStdString(toHex(data.data(), length));
    if (data.size() > length) {
        out += "…";
    }
    return out;
}

QString describePlaintext(const Bytes& data) {
    const std::string text = bytesToString(data);
    bool printable = !text.empty();
    for (unsigned char c : text) {
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
            printable = false;
            break;
        }
    }
    if (printable) {
        return QString::fromStdString(text);
    }
    return QString("（二进制数据 %1 字节）%2")
        .arg(data.size())
        .arg(QString::fromStdString(toHex(data.data(), std::min<std::size_t>(32, data.size()))));
}

/// 空闲等待：既用来等对端数据，也用来重新检查命令队列与停止标志。
/// 注意它**不再决定消息延迟**——`tryReceiveMessage()` 内部用 select() 等可读，
/// 对端一发数据就立刻返回，这里只是"没有数据时最多等多久再看一眼命令队列"。
constexpr int kIdleWaitMs = 100;
constexpr int kIoTimeoutMs = 5000;    ///< 已确认可读之后，读满一个完整包的兜底超时
constexpr int kHandshakeTimeoutMs = 8000;

}  // namespace

SessionWorker::SessionWorker(QObject* parent) : QObject(parent) {}

SessionWorker::~SessionWorker() {
    stopThread();
}

void SessionWorker::start(const UiConfig& config) {
    stopThread();  // 保证只有一个工作线程
    stopRequested_ = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
    }
    running_ = true;
    thread_ = std::thread(&SessionWorker::run, this, config);
}

void SessionWorker::stopThread() {
    stopRequested_ = true;
    condition_.notify_all();
    if (thread_.joinable()) {
        thread_.join();
    }
    running_ = false;
}

void SessionWorker::requestCloseAndStop() {
    push(Command{CommandKind::kClose, QString(), false});
}

void SessionWorker::requestSendText(const QString& text) {
    push(Command{CommandKind::kSendText, text, false});
}

void SessionWorker::requestSendFile(const QString& path, bool isImage) {
    push(Command{CommandKind::kSendFile, path, isImage});
}

void SessionWorker::requestSendCommand(const QString& command) {
    push(Command{CommandKind::kCommand, command, false});
}

void SessionWorker::requestTamper() {
    push(Command{CommandKind::kTamper, QString(), false});
}

void SessionWorker::requestReplay() {
    push(Command{CommandKind::kReplay, QString(), false});
}

void SessionWorker::push(const Command& command) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back(command);
    }
    condition_.notify_all();
}

bool SessionWorker::pop(Command& command) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
        return false;
    }
    command = queue_.front();
    queue_.pop_front();
    return true;
}

void SessionWorker::run(UiConfig config) {
    emit stateChanged("正在读取密钥与策略…");

    // ---------------- 1. 读取 K_master 与身份 ----------------
    KeyStoreConfig keys;
    std::string error;
    std::string warning;
    if (!KeyStore::loadFile(config.keyFile.toStdString(), keys, error, warning)) {
        emit sessionStopped(QString::fromStdString(error));
        running_ = false;
        return;
    }
    if (!warning.empty()) {
        emit logLine("[WARN] " + QString::fromStdString(warning));
    }

    // ---------------- 2. 访问控制策略 ----------------
    acl::AccessController accessController;
    std::string policyError;
    std::string policyWarning;
    if (!accessController.loadFile(config.policyFile.toStdString(), policyError, policyWarning)) {
        emit sessionStopped(QString::fromStdString(policyError));
        running_ = false;
        return;
    }
    if (!policyWarning.empty()) {
        emit logLine("[WARN] " + QString::fromStdString(policyWarning));
    }
    if (!config.accessLog.isEmpty()) {
        std::string logError;
        if (!accessController.setAuditLogFile(config.accessLog.toStdString(), logError)) {
            emit logLine("[WARN] " + QString::fromStdString(logError));
        }
    }

    // 攻击日志：与审计日志放在同一目录（默认 experiment_data/attack_log.txt）。
    // 单独一份文件，避免把"攻击演示"混进访问控制审计里。
    {
        const QString auditPath = config.accessLog;
        const int slash = auditPath.lastIndexOf('/');
        const QString dir = slash > 0 ? auditPath.left(slash) : QString("experiment_data");
        attackLogPath_ = dir + "/attack_log.txt";
        (void)ensureDirectory(dir.toStdString());
    }

    // ---------------- 3. 会话配置 ----------------
    SessionConfig sessionConfig;
    sessionConfig.localId = config.localId.toStdString();
    sessionConfig.peerId = config.peerId.toStdString();
    sessionConfig.host = config.host.toStdString();
    sessionConfig.port = config.port;
    sessionConfig.masterKey = keys.masterKey;
    sessionConfig.hasMasterKey = true;
    sessionConfig.handshakeTimeoutMs = kHandshakeTimeoutMs;
    sessionConfig.ioTimeoutMs = kIoTimeoutMs;     // 只在"包读了一半对端卡住"时兜底
    sessionConfig.logHandshake = true;            // 握手每一步都写日志（界面上能看到）
    // 握手每推进一步就通知界面（内核只回调 step 号，中文名由界面侧映射）。
    // 回调在工作线程执行，emit 的 Qt 信号会自动排队到 GUI 线程。
    sessionConfig.onHandshakeStep = [this](int step) {
        emit handshakeStep(step);
    };

    AesCryptoProvider crypto(nullptr);            // 真实 AES-CTR + 第一部分 CMAC
    SecureSession session(crypto, sessionConfig);
    transfer::TransferReceiver receiver(config.outDir.toStdString());

    emit logLine(QString("密码算法：%1").arg(QString::fromStdString(crypto.name())));
    emit logLine(QString("完整性算法：%1（%2）")
                     .arg(QString::fromStdString(crypto.macEngineName()))
                     .arg(crypto.macIsCryptographicallySecure() ? "密码学强度达标"
                                                                : "⚠ 占位实现"));
    emit logLine(QString("访问控制：本端角色 %1 [%2]")
                     .arg(QString::fromStdString(accessController.roleOf(sessionConfig.localId)))
                     .arg(QString::fromStdString(
                         accessController.permissionsOf(sessionConfig.localId).toString())));
    emit logLine(QString("          对端角色 %1 [%2]")
                     .arg(QString::fromStdString(accessController.roleOf(sessionConfig.peerId)))
                     .arg(QString::fromStdString(
                         accessController.permissionsOf(sessionConfig.peerId).toString())));

    // ---------------- 4. 建立会话（TCP + 完整握手）----------------
    emit stateChanged(config.isServer ? "正在监听…" : "正在连接…");
    if (config.isServer) {
        // 服务端：分片等待客户端接入（每 200 ms 醒一次），
        // 这样"等待中"也能立刻响应界面上的"断开"，不会卡死在 accept() 里。
        emit logLine("正在等待客户端接入…（可随时点击“断开”取消）");
        bool connected = false;
        while (!stopRequested_) {
            if (session.acceptOneClient(200)) {
                connected = true;
                break;
            }
            if (!session.lastAcceptTimedOut()) {
                emit sessionStopped("握手失败：" +
                                    QString::fromStdString(session.lastError()));
                running_ = false;
                return;
            }
        }
        if (!connected) {
            emit logLine("已取消等待客户端连接");
            emit sessionStopped("已主动断开（尚未等到客户端）");
            session.close();
            running_ = false;
            return;
        }
    } else if (!session.connectToServer()) {
        emit sessionStopped("握手失败：" + QString::fromStdString(session.lastError()));
        running_ = false;
        return;
    }

    // 摘要分两行：第一行会话指纹（SessionId / Nonce），第二行角色与权限。
    // 界面据此把"会话状态"卡片拆成两行显示（不再挤成一行）。
    emit sessionEstablished(
        QString("SessionId %1 ｜ NonceA %2 ｜ NonceB %3\n我的角色 %4 ｜ 权限 %5")
            .arg(QString::fromStdString(toHex(session.sessionId())))
            .arg(fromHexBytes(toBytes(session.nonceA())))
            .arg(fromHexBytes(toBytes(session.nonceB())))
            .arg(QString::fromStdString(accessController.roleOf(sessionConfig.localId)))
            .arg(QString::fromStdString(
                accessController.permissionsOf(sessionConfig.localId).toString())));
    emit stateChanged("安全会话已建立（ESTABLISHED）");
    emit logLine("✅ 安全会话建立完成：身份认证通过、会话密钥已分发并确认");

    // ---------------- 5. 收发循环 ----------------
    bool droppingTransfer = false;  // 被访问控制拒绝的传输：丢弃后续数据块，不落盘
    bool stoppedNotified = false;   // 是否已经发过 sessionStopped（避免重复/遗漏）
    while (!stopRequested_) {
        // 5.1 先执行界面下发的命令
        Command command;
        while (pop(command)) {
            const std::string peer = sessionConfig.peerId;
            if (command.kind == CommandKind::kClose) {
                (void)session.sendMessage(MessageType::kClose, Bytes{});
                emit logLine("已发送 CLOSE，结束会话");
                stopRequested_ = true;
                break;
            }
            if (command.kind == CommandKind::kSendText) {
                const Bytes body = stringToBytes(command.text.toStdString());
                if (accessController.isAllowed(sessionConfig.localId, acl::Operation::kSendMessage)) {
                    if (session.sendMessage(MessageType::kData, body)) {
                        emit messageReceived("我 → 对端", command.text, static_cast<int>(body.size()));
                    } else {
                        emit logLine("[ERROR] 发送失败：" +
                                     QString::fromStdString(session.lastError()));
                    }
                } else {
                    emit logLine("【访问控制】本端角色不允许 send_message，已拒绝发送");
                }
                continue;
            }
            if (command.kind == CommandKind::kCommand) {
                const QString payload = "CMD " + command.text;
                if (session.sendMessage(MessageType::kData,
                                        stringToBytes(payload.toStdString()))) {
                    emit logLine("→ 已发送应用层命令 " + command.text);
                } else {
                    emit logLine("[ERROR] 命令发送失败：" +
                                 QString::fromStdString(session.lastError()));
                }
                continue;
            }
            if (command.kind == CommandKind::kSendFile) {
                const transfer::Kind kind = command.isImage ? transfer::Kind::kImage
                                                            : transfer::Kind::kFile;
                const acl::Operation operation = command.isImage
                                                        ? acl::Operation::kSendImage
                                                        : acl::Operation::kSendFile;
                if (!accessController.isAllowed(sessionConfig.localId, operation)) {
                    emit logLine(QString("【访问控制】本端角色 %1 无权限 %2，已拒绝发送（服务端也会拒绝）")
                                     .arg(QString::fromStdString(accessController.roleOf(
                                         sessionConfig.localId)))
                                     .arg(acl::operationToString(operation)));
                    emit transferFinished(false, "本地策略拒绝：没有发送权限");
                    continue;
                }
                const QString name = QFileInfo(command.text).fileName();
                emit logLine(QString("开始发送%1：%2")
                                 .arg(command.isImage ? "图像" : "文件")
                                 .arg(name));
                const transfer::SendResult result = transfer::FileSender::send(
                    session, command.text.toStdString(), kind, false,
                    [this, name](std::uint64_t done, std::uint64_t total) {
                        emit transferProgress(name, static_cast<qint64>(done),
                                              static_cast<qint64>(total));
                    });
                if (!result.ok) {
                    emit transferFinished(false, QString::fromStdString(result.error));
                } else {
                    emit transferFinished(
                        true,
                        QString("%1 发送成功：%2 字节，%3 块，CRC32 0x%4，用时 %5 ms，吞吐 %6 MB/s")
                            .arg(name)
                            .arg(result.bytes)
                            .arg(result.chunks)
                            .arg(result.crc32, 8, 16, QChar('0'))
                            .arg(result.seconds * 1000.0, 0, 'f', 1)
                            .arg(result.megabytesPerSecond, 0, 'f', 2));
                }
                continue;
            }
            if (command.kind == CommandKind::kTamper || command.kind == CommandKind::kReplay) {
                const Bytes wire = session.lastSentWireForTesting();
                if (wire.empty()) {
                    emit logLine("[WARN] 还没有已发送的数据包，无法演示");
                    continue;
                }
                Bytes attack = wire;
                if (command.kind == CommandKind::kTamper) {
                    Packet packet;
                    if (!Packet::decode(wire, packet)) {
                        emit logLine("[WARN] 无法解析上一个数据包");
                        continue;
                    }
                    if (!packet.body.empty()) {
                        packet.body[0] = static_cast<Byte>(packet.body[0] ^ 0xFF);
                    }
                    packet.sequence += 1;
                    attack = packet.encodeWithMac();
                    lastAttackKind_ = "tamper";
                    emit logLine("【攻击演示】篡改上一个数据包的密文字节并重发（对端应拒绝）");
                } else {
                    lastAttackKind_ = "replay";
                    emit logLine("【攻击演示】原样重放上一个数据包（对端应判定为重放）");
                }
                if (!session.sendRawWireForTesting(attack)) {
                    emit logLine("[ERROR] 攻击包发送失败：" +
                                 QString::fromStdString(session.lastError()));
                }
                continue;
            }
            (void)peer;
        }
        if (stopRequested_) {
            break;
        }

        // 5.2 再尝试接收：等到有数据就立刻返回，没有数据则先回去处理命令队列。
        //     与旧实现的区别：不再把"接收超时"当成失败，也就不会再刷错误日志；
        //     对端消息的显示延迟不再受空闲等待时间限制。
        MessageType type = MessageType::kError;
        Bytes body;
        const SecureSession::ReceiveStatus status =
            session.tryReceiveMessage(type, body, kIdleWaitMs);
        if (status == SecureSession::ReceiveStatus::kNothing) {
            continue;  // 暂时没有数据：回到循环顶部处理命令/停止标志
        }
        if (status == SecureSession::ReceiveStatus::kClosed) {
            // 如果是被安全机制拦下的（篡改/重放/伪造…），在关闭前给对端回一条判定结果，
            // 让攻击端的界面也能显示"我倒在哪一关"；并留一份攻击日志。
            const RejectGate gate = session.lastRejectGate();
            if (attack::isAttackReject(gate) && session.state() == SessionState::kEstablished) {
                const std::string report = attack::formatAttackReport(
                    gate, session.receiveSequence(), session.lastError());
                if (!session.sendMessage(MessageType::kData, stringToBytes(report))) {
                    ST_LOG_DEBUG(kLogModule, "ATTACK-REPORT 发送失败（对端可能已关闭）");
                }
                attack::appendAttackLog(attackLogPath_.toStdString(), lastAttackKind_.toStdString(),
                                        gate, session.lastError());
                emit attackDetected(QString::fromUtf8(rejectGateToString(gate)),
                                    QString::fromStdString(session.lastError()));
                emit logLine(QString("【攻击演示】对端在第 %1 关拦下（%2），已回执并记录攻击日志")
                                 .arg(QString::fromUtf8(rejectGateToString(gate)))
                                 .arg(lastAttackKind_));
            }
            emit sessionStopped("接收失败（会话终止）：" +
                                QString::fromStdString(session.lastError()));
            stoppedNotified = true;
            break;
        }

        if (type == MessageType::kClose) {
            emit logLine("收到对端 CLOSE，会话正常结束");
            emit sessionStopped("对端主动结束了会话");
            stoppedNotified = true;
            break;
        }

        // 5.3 访问控制：服务端权威判定
        acl::Operation operation = acl::Operation::kSendMessage;
        const bool protectedOperation = acl::operationFromMessageType(type, operation);
        if (droppingTransfer &&
            (type == MessageType::kFileChunk || type == MessageType::kFileEnd)) {
            if (type == MessageType::kFileEnd) {
                droppingTransfer = false;
                emit logLine("（被拒绝的传输已丢弃完毕，对端未写入任何文件）");
            }
            continue;
        }
        if (type == MessageType::kFileStart || type == MessageType::kImage) {
            droppingTransfer = false;
        }
        if (protectedOperation &&
            !accessController.isAllowed(sessionConfig.peerId, operation)) {
            accessController.record(sessionConfig.peerId, operation, false, "服务端判定无权限");
            if (type == MessageType::kFileStart || type == MessageType::kImage) {
                droppingTransfer = true;
            }
            emit logLine(QString("【访问控制拒绝】%1（角色 %2）尝试 %3 —— 已拒绝，未执行")
                             .arg(config.peerId)
                             .arg(QString::fromStdString(
                                 accessController.roleOf(sessionConfig.peerId)))
                             .arg(acl::operationToString(operation)));
            (void)session.sendMessage(
                MessageType::kData,
                stringToBytes(std::string("ACCESS DENIED: ") +
                              acl::operationToString(operation) + " 需要更高权限（当前角色 " +
                              accessController.roleOf(sessionConfig.peerId) + "）"));
            emit statsUpdated(QString::fromStdString(session.stats().summary()));
            continue;
        }
        if (protectedOperation) {
            accessController.record(sessionConfig.peerId, operation, true, "");
        }

        // 5.4 应用层命令（CMD ...）
        const std::string text = bytesToString(body);
        if (text.rfind("CMD ", 0) == 0 && type == MessageType::kData) {
            const std::string cmd = text.substr(4);
            if (cmd == "WHOAMI") {
                (void)session.sendMessage(
                    MessageType::kData,
                    stringToBytes("ROLE " + accessController.roleOf(sessionConfig.peerId) + " : " +
                                  accessController.permissionsOf(sessionConfig.peerId).toString()));
                emit logLine("已回应 WHOAMI 查询");
            } else if (cmd == "VIEW_LOG") {
                if (!accessController.isAllowed(sessionConfig.peerId, acl::Operation::kViewLog)) {
                    accessController.record(sessionConfig.peerId, acl::Operation::kViewLog, false,
                                            "尝试查看审计日志");
                    (void)session.sendMessage(
                        MessageType::kData,
                        stringToBytes("ACCESS DENIED: view_log 仅管理员可用（当前角色 " +
                                      accessController.roleOf(sessionConfig.peerId) + "）"));
                    emit logLine("【访问控制拒绝】对端尝试查看审计日志（权限不足）");
                } else {
                    accessController.record(sessionConfig.peerId, acl::Operation::kViewLog, true, "");
                    const auto& decisions = accessController.recentDecisions();
                    std::string reply = "AUDIT LOG (最近 " + std::to_string(decisions.size()) +
                                        " 条，允许 " +
                                        std::to_string(accessController.allowedCount()) +
                                        " / 拒绝 " + std::to_string(accessController.deniedCount()) +
                                        ")";
                    const std::size_t begin = decisions.size() > 5 ? decisions.size() - 5 : 0;
                    for (std::size_t i = begin; i < decisions.size(); ++i) {
                        reply += "\n" + decisions[i];
                    }
                    (void)session.sendMessage(MessageType::kData, stringToBytes(reply));
                    emit logLine("已回应 VIEW_LOG（管理员）");
                }
            } else {
                (void)session.sendMessage(MessageType::kData,
                                          stringToBytes("UNKNOWN COMMAND: " + cmd));
            }
            emit statsUpdated(QString::fromStdString(session.stats().summary()));
            continue;
        }

        // 5.5 文件 / 图像传输
        std::string transferError;
        if (receiver.handle(type, body, &transferError)) {
            if (receiver.inProgress()) {
                emit transferProgress(QString::fromStdString(receiver.currentFileName()),
                                      static_cast<qint64>(receiver.receivedBytes()),
                                      static_cast<qint64>(receiver.expectedBytes()));
                continue;
            }
            const transfer::ReceiveResult& result = receiver.lastResult();
            if (!transferError.empty()) {
                emit logLine("[WARN] 传输处理异常：" + QString::fromStdString(transferError));
                (void)session.sendMessage(MessageType::kData,
                                          stringToBytes("FILE FAILED: " + transferError));
            } else {
                emit transferFinished(
                    result.ok,
                    QString("%1 接收%2：%3 字节，%4 块，CRC32 0x%5，保存于 %6")
                        .arg(QString::fromStdString(result.fileName))
                        .arg(result.ok ? "成功（校验通过）" : "失败")
                        .arg(result.bytes)
                        .arg(result.chunks)
                        .arg(result.crc32, 8, 16, QChar('0'))
                        .arg(QString::fromStdString(result.savedPath)));
                const std::string ackText =
                    (result.ok ? "FILE OK " : "FILE FAILED ") + result.fileName + " (" +
                    std::to_string(result.bytes) + " 字节)";
                (void)session.sendMessage(MessageType::kData, stringToBytes(ackText));
            }
            emit statsUpdated(QString::fromStdString(session.stats().summary()));
            continue;
        }

        // 5.6 普通短消息
        emit messageReceived(typeToText(type), describePlaintext(body),
                             static_cast<int>(body.size()));
        // 自动回复：只在收到"用户消息"时回一条 ACK，
        // 对 ACK / FILE OK / ROLE / AUDIT LOG 等回复型消息不再回复（否则会无限互相回复）
        if (shouldAutoReply(text)) {
            (void)session.sendMessage(
                MessageType::kData,
                stringToBytes("ACK: 已收到（" + std::to_string(body.size()) + " 字节）"));
        }
        emit statsUpdated(QString::fromStdString(session.stats().summary()));
    }

    emit statsUpdated(QString::fromStdString(session.stats().summary()));
    // 用户点"断开"时，循环会直接退出而不会走到上面的分支；
    // 这里统一补发一次 sessionStopped，界面才能把状态与按钮复位
    // （之前缺了这一步，界面会一直停在"正在结束会话…"，只能重启程序）。
    if (!stoppedNotified) {
        emit sessionStopped(stopRequested_ ? "已主动断开连接" : "会话已结束");
    }
    session.close();
    running_ = false;
}
