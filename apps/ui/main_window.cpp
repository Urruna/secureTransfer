// ============================================================================
//  SecureTransfer - 第三部分：Qt 图形界面主窗口（实现）
//  file: apps/ui/main_window.cpp
// ============================================================================

#include "main_window.h"

#include <QComboBox>
#include <QApplication>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSpinBox>
#include <QSizePolicy>
#include <QSplitter>
#include <QTextEdit>
#include <QTime>
#include <QTimer>
#include <QVBoxLayout>

#include <cstdio>
#include <initializer_list>

#include "common/path_utils.h"

namespace {

const char* const kColors[] = {"#c0392b", "#27ae60", "#f39c12"};

QString stamp() {
    return QTime::currentTime().toString("HH:mm:ss");
}

}  // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    worker_ = new SessionWorker(this);
    buildUi();

    connect(worker_, &SessionWorker::logLine, this, &MainWindow::appendLog);
    connect(worker_, &SessionWorker::stateChanged, this, &MainWindow::onStateChanged);
    connect(worker_, &SessionWorker::sessionEstablished, this, &MainWindow::onEstablished);
    connect(worker_, &SessionWorker::messageReceived, this, &MainWindow::onMessageReceived);
    connect(worker_, &SessionWorker::transferProgress, this, &MainWindow::onTransferProgress);
    connect(worker_, &SessionWorker::transferFinished, this, &MainWindow::onTransferFinished);
    connect(worker_, &SessionWorker::statsUpdated, this, &MainWindow::onStatsUpdated);
    connect(worker_, &SessionWorker::sessionStopped, this, &MainWindow::onSessionStopped);

    setSessionActive(false);
    appendLog("欢迎使用 SecureTransfer 图形界面。请选择角色并点击“启动/连接”。");
}

MainWindow::~MainWindow() = default;

// ---------------------------------------------------------------------------
//  界面搭建
// ---------------------------------------------------------------------------

void MainWindow::buildUi() {
    setWindowTitle("SecureTransfer — 安全的信息传输套件");
    // 默认尺寸要能放进 1366×768 这类笔记本屏幕（否则系统会把窗口压缩，
    // 控件被挤到"文字只显示一半"）；同时给出最小尺寸，保证再小也不会压变形。
    resize(1120, 700);
    setMinimumSize(960, 640);

    // ---- 左列：连接 + 会话 + 统计 ----
    auto* leftColumn = new QVBoxLayout();

    auto* connBox = new QGroupBox("1. 连接与身份");
    auto* connForm = new QFormLayout(connBox);
    // 长标签（例如"对端身份（握手校验）"）单独占一行，而不是把整个标签列撑到 200px，
    // 否则左列的"最小宽度"会远超滚动区可视宽度，右侧内容会被裁掉。
    connForm->setRowWrapPolicy(QFormLayout::WrapLongRows);
    roleBox_ = new QComboBox();
    roleBox_->addItems({"客户端（Alice，连接对端）", "服务端（Bob，等待连接）"});
    connForm->addRow("角色", roleBox_);

    hostEdit_ = new QLineEdit("127.0.0.1");
    connForm->addRow("对端地址", hostEdit_);
    portSpin_ = new QSpinBox();
    portSpin_->setRange(1, 65535);
    portSpin_->setValue(9000);
    connForm->addRow("端口", portSpin_);

    localIdBox_ = new QComboBox();
    localIdBox_->setEditable(true);
    localIdBox_->addItems({"alice", "eve", "mallory", "bob"});
    connForm->addRow("本端身份", localIdBox_);
    peerIdEdit_ = new QLineEdit("bob");
    connForm->addRow("对端身份（握手校验）", peerIdEdit_);

    keyFileEdit_ = new QLineEdit(resolvePath("configs/keys.conf", "."));
    policyFileEdit_ = new QLineEdit(resolvePath("configs/access_policy.conf", "."));
    outDirEdit_ = new QLineEdit(resolvePath("experiment_data/received", ".."));
    accessLogEdit_ = new QLineEdit(resolvePath("experiment_data/access_log.txt", ".."));
    connForm->addRow("密钥配置", keyFileEdit_);
    connForm->addRow("访问策略", policyFileEdit_);
    connForm->addRow("接收目录", outDirEdit_);
    connForm->addRow("审计日志", accessLogEdit_);

    startButton_ = new QPushButton("启动 / 连接");
    stopButton_ = new QPushButton("断开");
    auto* connButtons = new QHBoxLayout();
    connButtons->addWidget(startButton_);
    connButtons->addWidget(stopButton_);
    connForm->addRow(connButtons);
    leftColumn->addWidget(connBox);

    auto* stateBox = new QGroupBox("2. 安全会话状态");
    auto* stateLayout = new QVBoxLayout(stateBox);
    statusLabel_ = new QLabel("未连接");
    statusLabel_->setStyleSheet("font-weight: bold; color: #c0392b;");
    sessionInfoLabel_ = new QLabel("会话信息：—");
    sessionInfoLabel_->setWordWrap(true);
    roleInfoLabel_ = new QLabel("角色与权限：—");
    roleInfoLabel_->setWordWrap(true);
    stateLayout->addWidget(statusLabel_);
    stateLayout->addWidget(sessionInfoLabel_);
    stateLayout->addWidget(roleInfoLabel_);
    leftColumn->addWidget(stateBox);

    auto* statsBox = new QGroupBox("3. 统计与访问控制");
    auto* statsLayout = new QVBoxLayout(statsBox);
    statsLabel_ = new QLabel("收发统计：—");
    statsLabel_->setWordWrap(true);
    whoamiButton_ = new QPushButton("查询我的角色（WHOAMI）");
    viewLogButton_ = new QPushButton("查看审计日志（管理员）");
    statsLayout->addWidget(statsLabel_);
    statsLayout->addWidget(whoamiButton_);
    statsLayout->addWidget(viewLogButton_);
    leftColumn->addWidget(statsBox);
    leftColumn->addStretch();

    // ---- 右列：消息 + 文件 + 攻击演示 + 日志 ----
    auto* rightColumn = new QVBoxLayout();

    auto* messageBox = new QGroupBox("4. 短消息（全程加密 + 完整性保护）");
    auto* messageLayout = new QVBoxLayout(messageBox);
    historyEdit_ = new QTextEdit();
    historyEdit_->setReadOnly(true);
    historyEdit_->setMinimumHeight(110);
    inputEdit_ = new QLineEdit();
    inputEdit_->setPlaceholderText("输入要安全传输的短消息，回车或点击“发送”");
    sendButton_ = new QPushButton("发送");
    auto* sendRow = new QHBoxLayout();
    sendRow->addWidget(inputEdit_);
    sendRow->addWidget(sendButton_);
    messageLayout->addWidget(historyEdit_);
    messageLayout->addLayout(sendRow);
    rightColumn->addWidget(messageBox, 3);

    auto* transferBox = new QGroupBox("5. 文件 / 图像传输（自动分块 + 整文件 CRC32 校验）");
    auto* transferLayout = new QVBoxLayout(transferBox);
    auto* pickRow = new QHBoxLayout();
    pickFileButton_ = new QPushButton("选择文件…");
    pickImageButton_ = new QPushButton("选择图像…");
    pickRow->addWidget(pickFileButton_);
    pickRow->addWidget(pickImageButton_);
    pickRow->addStretch();
    progressBar_ = new QProgressBar();
    progressBar_->setRange(0, 100);
    progressBar_->setValue(0);
    transferLabel_ = new QLabel("尚未传输文件");
    transferLabel_->setWordWrap(true);
    transferLayout->addLayout(pickRow);
    transferLayout->addWidget(progressBar_);
    transferLayout->addWidget(transferLabel_);
    rightColumn->addWidget(transferBox, 2);

    auto* attackBox = new QGroupBox("6. Eve 攻击演示（验证完整性保护与防重放）");
    auto* attackLayout = new QHBoxLayout(attackBox);
    tamperButton_ = new QPushButton("篡改上一个数据包并重发");
    replayButton_ = new QPushButton("原样重放上一个数据包");
    attackLayout->addWidget(tamperButton_);
    attackLayout->addWidget(replayButton_);
    attackLayout->addStretch();
    rightColumn->addWidget(attackBox);

    auto* logBox = new QGroupBox("7. 运行日志（握手每一步、访问控制判定、传输细节）");
    auto* logLayout = new QVBoxLayout(logBox);
    logEdit_ = new QPlainTextEdit();
    logEdit_->setReadOnly(true);
    logEdit_->setMaximumBlockCount(2000);
    logEdit_->setMinimumHeight(130);
    logLayout->addWidget(logEdit_);
    rightColumn->addWidget(logBox, 2);

    // 文本区会随内容增长而抬高 sizeHint，进而把整列撑大、把上面的控件压变形。
    // 让它们在垂直方向"忽略 sizeHint"：高度完全由布局按剩余空间分配
    // （配合上面的最小高度，既不会被压没，也不会挤别人）。
    historyEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
    logEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);

    // 给每个输入类控件设"最小高度 = 它自己的 sizeHint 高度"：
    // 窗口变小、空间不够时，布局最多把它们压到最合适的尺寸，
    // 不会再把按钮/下拉框压成 28px 这种"文字只剩半行"的状态。
    const std::initializer_list<QWidget*> inputs = {
        roleBox_,        hostEdit_,       portSpin_,       localIdBox_,      peerIdEdit_,
        keyFileEdit_,    policyFileEdit_, outDirEdit_,     accessLogEdit_,   startButton_,
        stopButton_,     inputEdit_,      sendButton_,     pickFileButton_,  pickImageButton_,
        whoamiButton_,   viewLogButton_,  tamperButton_,   replayButton_,
    };
    for (QWidget* w : inputs) {
        w->setMinimumHeight(w->sizeHint().height());
    }

    auto* central = new QWidget();
    auto* mainLayout = new QHBoxLayout(central);
    auto* leftWidget = new QWidget();
    leftWidget->setLayout(leftColumn);
    // 左列放进滚动区：屏幕/窗口不够高时出现滚动条，而不是把控件压扁
    leftScroll_ = new QScrollArea();
    leftScroll_->setWidget(leftWidget);
    leftScroll_->setWidgetResizable(true);
    leftScroll_->setFrameShape(QFrame::NoFrame);
    // 内容比可视区宽时**必须**能滚动，否则文字会被静默裁掉（之前就是这个问题）。
    leftScroll_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    leftScroll_->setMaximumWidth(560);
    auto* rightWidget = new QWidget();
    rightWidget->setLayout(rightColumn);
    mainLayout->addWidget(leftScroll_);
    mainLayout->addWidget(rightWidget, 1);
    setCentralWidget(central);

    // ---- 信号连接 ----
    connect(startButton_, &QPushButton::clicked, this, &MainWindow::onStartClicked);
    connect(stopButton_, &QPushButton::clicked, this, &MainWindow::onStopClicked);
    connect(roleBox_, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &MainWindow::onRoleChanged);
    connect(sendButton_, &QPushButton::clicked, this, &MainWindow::onSendText);
    connect(inputEdit_, &QLineEdit::returnPressed, this, &MainWindow::onSendText);
    connect(pickFileButton_, &QPushButton::clicked, this, &MainWindow::onPickFile);
    connect(pickImageButton_, &QPushButton::clicked, this, &MainWindow::onPickImage);
    connect(whoamiButton_, &QPushButton::clicked, this, &MainWindow::onWhoAmI);
    connect(viewLogButton_, &QPushButton::clicked, this, &MainWindow::onViewLog);
    connect(tamperButton_, &QPushButton::clicked, this, &MainWindow::onTamper);
    connect(replayButton_, &QPushButton::clicked, this, &MainWindow::onReplay);
    onRoleChanged();
}

QString MainWindow::resolvePath(const QString& relative, const QString& directory) const {
    const QStringList candidates = {
        directory + "/" + relative,
        directory + "/../" + relative,
        "/home/securityTransfer/" + relative,
        relative,
    };
    for (const QString& candidate : candidates) {
        if (QFileInfo::exists(candidate)) {
            return QDir(candidate).absolutePath();
        }
    }
    return relative;
}

void MainWindow::setSessionActive(bool active) {
    startButton_->setEnabled(!active);
    stopButton_->setEnabled(active);
    sendButton_->setEnabled(active);
    pickFileButton_->setEnabled(active);
    pickImageButton_->setEnabled(active);
    whoamiButton_->setEnabled(active);
    viewLogButton_->setEnabled(active);
    tamperButton_->setEnabled(active);
    replayButton_->setEnabled(active);
}

// ---------------------------------------------------------------------------
//  按钮槽函数
// ---------------------------------------------------------------------------

void MainWindow::onRoleChanged() {
    const bool isServer = roleBox_->currentIndex() == 1;
    hostEdit_->setEnabled(!isServer);
    peerIdEdit_->setText(isServer ? "alice" : "bob");
    localIdBox_->setCurrentText(isServer ? "bob" : "alice");
    appendLog(isServer ? "已选择服务端角色（Bob）：点击“启动/连接”后等待对端接入。"
                       : "已选择客户端角色（Alice）：点击“启动/连接”后连接到对端。");
}

void MainWindow::onStartClicked() {
    const UiConfig config = collectConfig();
    if (!QFileInfo::exists(config.keyFile)) {
        QMessageBox::warning(this, "缺少密钥文件",
                             "找不到密钥配置文件：\n" + config.keyFile +
                                 "\n\n可复制 configs/keys.conf.example 生成。");
        return;
    }
    if (!QFileInfo::exists(config.policyFile)) {
        QMessageBox::warning(this, "缺少策略文件", "找不到访问控制策略：\n" + config.policyFile);
        return;
    }
    (void)ensureDirectory(config.outDir.toStdString());
    statusLabel_->setText("连接中…");
    statusLabel_->setStyleSheet("font-weight: bold; color: #f39c12;");
    appendLog(QString("===== 开始会话：%1，本端 %2，对端 %3，端口 %4 =====")
                  .arg(config.isServer ? "服务端" : "客户端")
                  .arg(config.localId)
                  .arg(config.peerId)
                  .arg(config.port));
    setSessionActive(true);
    worker_->start(config);
}

void MainWindow::onStopClicked() {
    appendLog("正在结束会话…");
    worker_->requestCloseAndStop();
}

void MainWindow::onSendText() {
    const QString text = inputEdit_->text();
    if (text.isEmpty()) {
        return;
    }
    worker_->requestSendText(text);
    inputEdit_->clear();
}

void MainWindow::onPickFile() {
    const QString path = QFileDialog::getOpenFileName(this, "选择要安全传输的文件",
                                                      lastSendDirectory_);
    if (path.isEmpty()) {
        return;
    }
    lastSendDirectory_ = QFileInfo(path).absolutePath();
    progressBar_->setValue(0);
    worker_->requestSendFile(path, false);
}

void MainWindow::onPickImage() {
    const QString path = QFileDialog::getOpenFileName(
        this, "选择要安全传输的图像", lastSendDirectory_,
        "图像 (*.png *.jpg *.jpeg *.bmp *.gif);;所有文件 (*)");
    if (path.isEmpty()) {
        return;
    }
    lastSendDirectory_ = QFileInfo(path).absolutePath();
    progressBar_->setValue(0);
    worker_->requestSendFile(path, true);
}

void MainWindow::onWhoAmI() {
    worker_->requestSendCommand("WHOAMI");
}

void MainWindow::onViewLog() {
    worker_->requestSendCommand("VIEW_LOG");
}

void MainWindow::onTamper() {
    appendLog("⚠ 触发攻击演示：篡改上一个数据包（对端应拒绝并终止会话）");
    worker_->requestTamper();
}

void MainWindow::onReplay() {
    appendLog("⚠ 触发攻击演示：重放上一个数据包（对端应判定为重放）");
    worker_->requestReplay();
}

// ---------------------------------------------------------------------------
//  工作线程信号
// ---------------------------------------------------------------------------

UiConfig MainWindow::collectConfig() const {
    UiConfig config;
    config.isServer = roleBox_->currentIndex() == 1;
    config.host = hostEdit_->text().trimmed();
    config.port = static_cast<quint16>(portSpin_->value());
    config.localId = localIdBox_->currentText().trimmed();
    config.peerId = peerIdEdit_->text().trimmed();
    config.keyFile = keyFileEdit_->text().trimmed();
    config.policyFile = policyFileEdit_->text().trimmed();
    config.outDir = outDirEdit_->text().trimmed();
    config.accessLog = accessLogEdit_->text().trimmed();
    return config;
}

void MainWindow::appendLog(const QString& text) {
    logEdit_->appendPlainText(QString("[%1] %2").arg(stamp()).arg(text));
}

void MainWindow::onStateChanged(const QString& state) {
    statusLabel_->setText(state);
    appendLog(state);
}

void MainWindow::onEstablished(const QString& summary) {
    statusLabel_->setText("安全会话已建立（ESTABLISHED）");
    statusLabel_->setStyleSheet("font-weight: bold; color: #27ae60;");
    sessionInfoLabel_->setText("会话信息：" + summary);
    appendLog("会话信息：" + summary);

    // 命令行预置动作：会话建立后按顺序执行（用于自动演示与截图）
    if (!handshakeDone_) {
        handshakeDone_ = true;
        const QVector<QPair<QString, QString>> actions = pendingActions_;
        pendingActions_.clear();
        for (const auto& action : actions) {
            const QString kind = action.first;
            const QString value = action.second;
            if (kind == "text") {
                appendLog("[自动] 发送短消息：" + value);
                worker_->requestSendText(value);
            } else if (kind == "cmd") {
                appendLog("[自动] 发送命令：" + value);
                worker_->requestSendCommand(value);
            } else if (kind == "file") {
                appendLog("[自动] 发送文件：" + value);
                progressBar_->setValue(0);
                worker_->requestSendFile(value, false);
            } else if (kind == "image") {
                appendLog("[自动] 发送图像：" + value);
                progressBar_->setValue(0);
                worker_->requestSendFile(value, true);
            }
        }
    }
}

void MainWindow::applyOptions(const Options& options) {
    if (options.roleSpecified) {
        roleBox_->setCurrentIndex(options.isServer ? 1 : 0);
    }
    if (!options.host.isEmpty()) {
        hostEdit_->setText(options.host);
    }
    if (options.port > 0) {
        portSpin_->setValue(options.port);
    }
    if (!options.localId.isEmpty()) {
        localIdBox_->setCurrentText(options.localId);
    }
    if (!options.peerId.isEmpty()) {
        peerIdEdit_->setText(options.peerId);
    }
    if (!options.keyFile.isEmpty()) {
        keyFileEdit_->setText(options.keyFile);
    }
    if (!options.policyFile.isEmpty()) {
        policyFileEdit_->setText(options.policyFile);
    }
    if (!options.outDir.isEmpty()) {
        outDirEdit_->setText(options.outDir);
    }
    if (!options.accessLog.isEmpty()) {
        accessLogEdit_->setText(options.accessLog);
    }
    pendingActions_ = options.actions;
    if (!options.geometry.isEmpty()) {
        // "宽x高"：便于在小窗口下复现布局问题（例如 --geometry 940x600）
        const QStringList parts = options.geometry.split(QLatin1Char('x'));
        if (parts.size() == 2 && !parts.at(0).isEmpty() && !parts.at(1).isEmpty()) {
            resize(parts.at(0).toInt(), parts.at(1).toInt());
        }
    }
    if (options.printGeometry) {
        // 等 show() 之后布局稳定下来再打印，然后退出（用于排查"文字被压扁"这类问题）
        QTimer::singleShot(600, this, [this]() {
            printGeometry();
            QApplication::quit();
        });
    }
    if (options.autoStart) {
        appendLog("命令行指定了 --auto：自动开始会话");
        onStartClicked();
    }
}

void MainWindow::printGeometry() const {
    const auto dump = [](const char* name, const QWidget* w) {
        if (w == nullptr) {
            return;
        }
        std::printf("%-14s %4d x %-4d  minimumHeight=%3d  sizeHintHeight=%3d\n", name, w->width(),
                    w->height(), w->minimumHeight(), w->sizeHint().height());
    };

    std::printf("window         %4d x %-4d  minimum=%d x %d  dpr=%.2f\n", width(), height(),
                minimumWidth(), minimumHeight(), devicePixelRatioF());
    dump("roleBox", roleBox_);
    dump("hostEdit", hostEdit_);
    dump("portSpin", portSpin_);
    dump("localIdBox", localIdBox_);
    dump("peerIdEdit", peerIdEdit_);
    dump("keyFileEdit", keyFileEdit_);
    dump("policyFileEdit", policyFileEdit_);
    dump("outDirEdit", outDirEdit_);
    dump("accessLogEdit", accessLogEdit_);
    dump("startButton", startButton_);
    dump("stopButton", stopButton_);
    dump("inputEdit", inputEdit_);
    dump("sendButton", sendButton_);
    dump("pickFileButton", pickFileButton_);
    dump("pickImageButton", pickImageButton_);
    dump("whoamiButton", whoamiButton_);
    dump("viewLogButton", viewLogButton_);
    dump("tamperButton", tamperButton_);
    dump("replayButton", replayButton_);
    dump("historyEdit", historyEdit_);
    dump("logEdit", logEdit_);

    // 左列是滚动区：如果 viewport 比内容窄，内容就会被裁掉（表现就是"左边几列文字看不到"）
    if (leftScroll_ != nullptr) {
        const QWidget* inner = leftScroll_->widget();
        std::printf("leftScroll     viewport=%d x %d  innerWidget=%d x %d  "
                    "hScroll=%d vScroll=%d  innerMinWidth=%d\n",
                    leftScroll_->viewport()->width(), leftScroll_->viewport()->height(),
                    inner != nullptr ? inner->width() : -1, inner != nullptr ? inner->height() : -1,
                    leftScroll_->horizontalScrollBar()->value(),
                    leftScroll_->verticalScrollBar()->value(),
                    inner != nullptr ? inner->minimumSizeHint().width() : -1);
    }

    // 所有标签/分组框：宽度小于 sizeHint 就说明文字被裁（省略号或直接消失）
    for (const QLabel* label : findChildren<QLabel*>()) {
        if (label->isVisible() && !label->text().isEmpty()) {
            std::printf("label  %-26s w=%4d  sizeHintW=%4d  text=%s\n",
                        "QLabel", label->width(), label->sizeHint().width(),
                        label->text().left(24).toUtf8().constData());
        }
    }
    for (const QGroupBox* box : findChildren<QGroupBox*>()) {
        if (box->isVisible()) {
            std::printf("group  w=%4d  x=%4d  sizeHintW=%4d  %s\n", box->width(), box->x(),
                        box->sizeHint().width(), box->title().toUtf8().constData());
        }
    }
    std::fflush(stdout);
}

void MainWindow::onMessageReceived(const QString& type, const QString& text, int bytes) {
    historyEdit_->append(QString("[%1] %2（%3 字节）：%4")
                             .arg(stamp())
                             .arg(type)
                             .arg(bytes)
                             .arg(text));
}

void MainWindow::onTransferProgress(const QString& name, qint64 done, qint64 total) {
    if (total <= 0) {
        return;
    }
    progressBar_->setValue(static_cast<int>(done * 100 / total));
    transferLabel_->setText(QString("%1：%2 / %3 字节（%4%）")
                                .arg(name)
                                .arg(done)
                                .arg(total)
                                .arg(done * 100 / total));
}

void MainWindow::onTransferFinished(bool ok, const QString& summary) {
    progressBar_->setValue(ok ? 100 : 0);
    transferLabel_->setText((ok ? "✅ " : "❌ ") + summary);
    appendLog((ok ? "[传输成功] " : "[传输失败] ") + summary);
}

void MainWindow::onStatsUpdated(const QString& summary) {
    statsLabel_->setText("收发统计：" + summary);
}

void MainWindow::onSessionStopped(const QString& reason) {
    statusLabel_->setText("会话已结束");
    statusLabel_->setStyleSheet("font-weight: bold; color: #c0392b;");
    appendLog("会话结束：" + reason);
    setSessionActive(false);
}
