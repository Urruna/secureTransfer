// ============================================================================
//  SecureTransfer - 第三部分：Qt 图形界面主窗口
//  file: apps/ui/main_window.h
//
//  布局（视觉与分区以 docs/SecureTransfer_UI改造草图.html 为准）：
//    标题条 → 工具条 → 三栏（会话/握手/连接设置 │ 消息/文件/Eve │ 统计/日志）
//    → 状态栏
// ============================================================================

#ifndef SECURETRANSFER_APPS_UI_MAIN_WINDOW_H
#define SECURETRANSFER_APPS_UI_MAIN_WINDOW_H

#include <QColor>
#include <QDateTime>
#include <QMainWindow>
#include <QPair>
#include <QString>
#include <QVector>

#include "session_worker.h"

class QComboBox;
class QDialog;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QScrollArea;
class QSpinBox;
class QTextEdit;
class QTimer;

/// 握手共 7 步（与 security/session.h 的 onHandshakeStep 回调一致）
inline constexpr int kHandshakeSteps = 7;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    /// 命令行参数（便于演示与自动截图：`--auto` 会立刻开始会话，
    /// 并可按顺序自动发送文本 / 文件 / 图像 / 命令）。
    struct Options {
        bool autoStart = false;
        bool isServer = false;
        bool roleSpecified = false;
        QString host;
        int port = -1;
        QString localId;
        QString peerId;
        QString keyFile;
        QString policyFile;
        QString outDir;
        QString accessLog;
        QVector<QPair<QString, QString>> actions;  ///< ("text"/"file"/"image"/"cmd", 参数)
        QString geometry;                          ///< "宽x高"：强制窗口尺寸（例如 940x600）
        bool printGeometry = false;                ///< 打印各控件实际尺寸后退出（排查布局问题）
    };

    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    /// 应用命令行参数（在 show() 之前调用）。
    void applyOptions(const Options& options);

private slots:
    void onStartClicked();
    void onStopClicked();
    void onRoleChanged();
    void onSendText();
    void onPickFile();
    void onPickImage();
    void onWhoAmI();
    void onViewLog();
    void onTamper();
    void onReplay();

    void appendLog(const QString& text);
    void onStateChanged(const QString& state);
    void onEstablished(const QString& summary);
    void onMessageReceived(const QString& type, const QString& text, int bytes);
    void onTransferProgress(const QString& name, qint64 done, qint64 total);
    void onTransferFinished(bool ok, const QString& summary);
    void onStatsUpdated(const QString& summary);
    void onSessionStopped(const QString& reason);
    /// Eve 攻击面板：对端（或被本端）判定出的拦截关卡
    void onAttackDetected(const QString& gate, const QString& reason);
    /// 高级设置（建链参数：对端身份 / 密钥 / 策略 / 目录 / 审计日志）
    void onAdvancedSettings();
    /// 导出运行日志
    void onExportLog();
    /// 日志级别 / 关键字过滤条件变化
    void onLogFilterChanged();
    /// 握手进度（0 = 未开始，1..7 = 已完成到第几步）
    void setHandshakeStep(int step);

private:
    /// 一条日志（级别用于着色与过滤）
    struct LogEntry {
        int level = 0;
        QString text;
    };

    void buildUi();
    QWidget* buildLeftColumn();
    QWidget* buildCenterColumn();
    QWidget* buildRightColumn();
    void buildAdvancedDialog();
    void connectSignals();

    UiConfig collectConfig() const;
    QString resolvePath(const QString& relative, const QString& directory) const;
    void setSessionActive(bool active);
    /// 根据当前状态更新标题条 / 会话状态卡片（文字 + 灯色）
    void setStatusIndicator(const QString& text, const QColor& color);
    /// 刷新左栏「连接设置」里的对端/密钥/策略摘要
    void updateSummaries();
    /// 刷新状态栏（端口 / 算法 / 会话时长 / 就绪）
    void updateStatusBar();

    /// 按当前过滤条件重新渲染日志视图
    void renderLog();
    /// 追加一条带级别的日志（level 见 stui::LogLevel）
    void appendLogWithLevel(int level, const QString& text);
    bool logPassesFilter(const LogEntry& entry) const;
    /// 打印窗口与关键控件的实际尺寸，用于确认"文字被压扁/显示不全"这类布局问题。
    void printGeometry() const;

    SessionWorker* worker_ = nullptr;

    QVector<LogEntry> logEntries_;

    // ---- 外壳 ----
    QLabel* statusDot_ = nullptr;
    QLabel* statusText_ = nullptr;
    QLabel* statusBarInfo_ = nullptr;
    QLabel* statusReadyLabel_ = nullptr;
    QTimer* sessionTimer_ = nullptr;
    QDateTime sessionStart_;

    // ---- 统计数字块（草图右栏 2×2） ----
    QLabel* tileRecv_ = nullptr;
    QLabel* tileSent_ = nullptr;
    QLabel* tileReject_ = nullptr;
    QLabel* tileThroughput_ = nullptr;

    // ---- 握手进度（7 步） ----
    QLabel* handshakeDots_[kHandshakeSteps] = {};
    QLabel* handshakeHint_ = nullptr;
    int currentHandshakeStep_ = 0;

    // ---- 左栏摘要 ----
    QLabel* peerSummaryLabel_ = nullptr;
    QLabel* pathSummaryLabel_ = nullptr;

    // ---- Eve 攻击面板 ----
    QLabel* attackResultLabel_ = nullptr;
    QString lastAttackAction_;

    // ---- 日志过滤 / 导出 ----
    QComboBox* logLevelBox_ = nullptr;
    QLineEdit* logFilterEdit_ = nullptr;
    QPushButton* exportLogButton_ = nullptr;

    // ---- 高级设置 ----
    QPushButton* advancedButton_ = nullptr;
    QDialog* advancedDialog_ = nullptr;

    // ---- 连接设置（主界面保留：角色 / 对端地址 / 端口 / 本端身份） ----
    QComboBox* roleBox_ = nullptr;
    QLineEdit* hostEdit_ = nullptr;
    QSpinBox* portSpin_ = nullptr;
    QComboBox* localIdBox_ = nullptr;
    QPushButton* startButton_ = nullptr;
    QPushButton* stopButton_ = nullptr;

    // ---- 高级设置里的建链参数 ----
    QLineEdit* peerIdEdit_ = nullptr;
    QLineEdit* keyFileEdit_ = nullptr;
    QLineEdit* policyFileEdit_ = nullptr;
    QLineEdit* outDirEdit_ = nullptr;
    QLineEdit* accessLogEdit_ = nullptr;

    // ---- 会话状态 ----
    QLabel* statusLabel_ = nullptr;
    QLabel* sessionInfoLabel_ = nullptr;
    QLabel* roleInfoLabel_ = nullptr;

    // ---- 消息 ----
    QTextEdit* historyEdit_ = nullptr;
    QLineEdit* inputEdit_ = nullptr;
    QPushButton* sendButton_ = nullptr;

    // ---- 文件 / 图像 ----
    QPushButton* pickFileButton_ = nullptr;
    QPushButton* pickImageButton_ = nullptr;
    QProgressBar* progressBar_ = nullptr;
    QLabel* transferLabel_ = nullptr;

    // ---- 访问控制与攻击演示 ----
    QPushButton* whoamiButton_ = nullptr;
    QPushButton* viewLogButton_ = nullptr;
    QPushButton* tamperButton_ = nullptr;
    QPushButton* replayButton_ = nullptr;

    QPlainTextEdit* logEdit_ = nullptr;
    QScrollArea* leftScroll_ = nullptr;  ///< 左列的滚动区（小窗口时可滚动，不挤压控件）
    QString lastSendDirectory_;
    QVector<QPair<QString, QString>> pendingActions_;
    bool handshakeDone_ = false;
};

#endif  // SECURETRANSFER_APPS_UI_MAIN_WINDOW_H
