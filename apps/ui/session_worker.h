// ============================================================================
//  SecureTransfer - 第三部分：Qt 图形界面的会话工作线程
//  file: apps/ui/session_worker.h
//
//  为什么要单独一个线程：
//    `SecureSession::receiveMessage()` 是阻塞的。如果直接在 Qt 的 GUI 线程里调用，
//    界面会卡死。所以这里把"安全会话"整体放在一个工作线程里：
//      * GUI 线程只负责画界面，通过队列下发命令（发送消息、发文件、发命令…）；
//      * 工作线程负责握手、收发、文件传输、访问控制判定，并把结果用信号发回 GUI。
//
//  线程安全约定：
//    `request*()` 系列方法只往队列里塞命令（加锁），可以在 GUI 线程随便调用；
//    真正的 `SecureSession` 调用**只在工作线程里发生**（该对象不是线程安全的）。
// ============================================================================

#ifndef SECURETRANSFER_APPS_UI_SESSION_WORKER_H
#define SECURETRANSFER_APPS_UI_SESSION_WORKER_H

#include <QObject>
#include <QString>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

/// 界面传进来的会话配置。
struct UiConfig {
    bool isServer = false;      ///< true = Bob（监听），false = Alice（连接）
    QString host = "127.0.0.1";
    quint16 port = 9000;
    QString localId;            ///< 本端身份（alice / eve / mallory / bob）
    QString peerId;             ///< 对端身份（握手时会校验）
    QString keyFile;            ///< keys.conf
    QString policyFile;         ///< access_policy.conf
    QString outDir;             ///< 接收文件目录
    QString accessLog;          ///< 审计日志
};

/// 会话工作线程：把 SecureSession 的所有调用都收在这一个线程里。
class SessionWorker : public QObject {
    Q_OBJECT

public:
    explicit SessionWorker(QObject* parent = nullptr);
    ~SessionWorker() override;

    SessionWorker(const SessionWorker&) = delete;
    SessionWorker& operator=(const SessionWorker&) = delete;

    /// 启动工作线程（内部完成 TCP 连接/监听 + 完整握手）。
    void start(const UiConfig& config);

    /// 请求结束（发送 CLOSE 并退出循环）。
    void requestCloseAndStop();

    // ---- 以下方法线程安全：只把命令放进队列 ----
    void requestSendText(const QString& text);
    void requestSendFile(const QString& path, bool isImage);
    void requestSendCommand(const QString& command);  ///< WHOAMI / VIEW_LOG
    void requestTamper();                             ///< 攻击演示：篡改上一个包
    void requestReplay();                             ///< 攻击演示：重放上一个包

signals:
    void logLine(const QString& text);
    void stateChanged(const QString& state);
    void sessionEstablished(const QString& summary);
    void messageReceived(const QString& type, const QString& text, int bytes);
    void transferProgress(const QString& name, qint64 done, qint64 total);
    void transferFinished(bool ok, const QString& summary);
    void statsUpdated(const QString& summary);
    void sessionStopped(const QString& reason);

private:
    enum class CommandKind { kSendText, kSendFile, kCommand, kTamper, kReplay, kClose };
    struct Command {
        CommandKind kind = CommandKind::kSendText;
        QString text;
        bool isImage = false;
    };

    void run(UiConfig config);           ///< 工作线程主函数
    void push(const Command& command);
    bool pop(Command& command);
    void stopThread();

    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<Command> queue_;
    std::atomic<bool> stopRequested_{false};
    std::atomic<bool> running_{false};
};

#endif  // SECURETRANSFER_APPS_UI_SESSION_WORKER_H
