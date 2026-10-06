// ============================================================================
//  SecureTransfer - 第三部分：Qt 图形界面主窗口
//  file: apps/ui/main_window.h
// ============================================================================

#ifndef SECURETRANSFER_APPS_UI_MAIN_WINDOW_H
#define SECURETRANSFER_APPS_UI_MAIN_WINDOW_H

#include <QMainWindow>
#include <QPair>
#include <QString>
#include <QVector>

#include "session_worker.h"

class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QScrollArea;
class QSpinBox;
class QTextEdit;

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

private:
    void buildUi();
    UiConfig collectConfig() const;
    QString resolvePath(const QString& relative, const QString& directory) const;
    void setSessionActive(bool active);
    /// 打印窗口与关键控件的实际尺寸，用于确认"文字被压扁/显示不全"这类布局问题。
    void printGeometry() const;

    SessionWorker* worker_ = nullptr;

    // 连接与身份
    QComboBox* roleBox_ = nullptr;
    QLineEdit* hostEdit_ = nullptr;
    QSpinBox* portSpin_ = nullptr;
    QComboBox* localIdBox_ = nullptr;
    QLineEdit* peerIdEdit_ = nullptr;
    QLineEdit* keyFileEdit_ = nullptr;
    QLineEdit* policyFileEdit_ = nullptr;
    QLineEdit* outDirEdit_ = nullptr;
    QLineEdit* accessLogEdit_ = nullptr;
    QPushButton* startButton_ = nullptr;
    QPushButton* stopButton_ = nullptr;

    // 会话状态
    QLabel* statusLabel_ = nullptr;
    QLabel* sessionInfoLabel_ = nullptr;
    QLabel* roleInfoLabel_ = nullptr;
    QLabel* statsLabel_ = nullptr;

    // 消息
    QTextEdit* historyEdit_ = nullptr;
    QLineEdit* inputEdit_ = nullptr;
    QPushButton* sendButton_ = nullptr;

    // 文件 / 图像
    QPushButton* pickFileButton_ = nullptr;
    QPushButton* pickImageButton_ = nullptr;
    QProgressBar* progressBar_ = nullptr;
    QLabel* transferLabel_ = nullptr;

    // 访问控制与攻击演示
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
