// ============================================================================
//  SecureTransfer - 第三部分：Qt 图形界面主窗口（实现）
//  file: apps/ui/main_window.cpp
//
//  分区（与 docs/SecureTransfer_UI改造草图.html 一致）：
//    标题条 → 工具条 → 三栏 → 状态栏
//  三栏：左 = 会话状态 / 握手进度 / 连接设置
//        中 = 短消息 / 文件图像传输 / Eve 攻击演示
//        右 = 统计数字块 / 运行日志（分级 + 过滤 + 导出）
// ============================================================================

#include "main_window.h"

#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
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
#include <QSizePolicy>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QTextEdit>
#include <QTextStream>
#include <QTime>
#include <QTimer>
#include <QVBoxLayout>

#include <cstdio>
#include <initializer_list>

#include "app_theme.h"
#include "common/path_utils.h"

namespace {

/// 握手 7 步的名字（由界面侧给出；内核只回调 step 号，不发中文文案）。
const char* const kHandshakeStepNames[kHandshakeSteps] = {
    "HELLO", "HELLO_ACK", "AUTH", "密钥请求", "密钥分发", "密钥确认", "确认应答",
};

/// 日志最多保留多少条（与 logEdit_ 的 maximumBlockCount 保持一致）
constexpr int kMaxLogEntries = 2000;

QString stamp() {
    return QTime::currentTime().toString("HH:mm:ss");
}

/// 从 `sent=12 recv=34 …` 这样的统计摘要里取出一个字段（取不到返回空串）。
QString statToken(const QString& summary, const QString& key) {
    const QString needle = key + "=";
    const int index = summary.indexOf(needle);
    if (index < 0) {
        return QString();
    }
    const int begin = index + needle.size();
    int end = begin;
    while (end < summary.size() && !summary.at(end).isSpace()) {
        ++end;
    }
    return summary.mid(begin, end - begin);
}

/// 从日志文本推断级别：worker 的日志带 [WARN] / [ERROR] / ✅ / 【访问控制拒绝】等前缀，
/// 在这里统一归类，UI 只维护一处映射（将来升级为结构化信号也只需改这一个函数）。
int classifyLogLevel(const QString& text) {
    if (text.contains("[ERROR]") || text.contains("❌") || text.contains("【访问控制拒绝】") ||
        text.contains("失败")) {
        return static_cast<int>(stui::LogLevel::kError);
    }
    if (text.contains("[WARN]") || text.contains("⚠") || text.contains("【攻击演示】")) {
        return static_cast<int>(stui::LogLevel::kWarn);
    }
    if (text.contains("✅") || text.contains("成功")) {
        return static_cast<int>(stui::LogLevel::kSuccess);
    }
    return static_cast<int>(stui::LogLevel::kInfo);
}

const char* logLevelName(int level) {
    switch (static_cast<stui::LogLevel>(level)) {
        case stui::LogLevel::kSuccess: return "OK";
        case stui::LogLevel::kWarn: return "WARN";
        case stui::LogLevel::kError: return "ERROR";
        case stui::LogLevel::kInfo: break;
    }
    return "INFO";
}

/// 状态灯（标题条右侧的小圆点）。
QLabel* makeDot(const QString& color) {
    auto* dot = new QLabel();
    dot->setFixedSize(9, 9);
    dot->setStyleSheet(QString("background:%1;border-radius:4px;").arg(color));
    return dot;
}

/// 工具条里的竖分隔线。
QFrame* makeSeparator() {
    auto* line = new QFrame();
    line->setFrameShape(QFrame::VLine);
    line->setFixedWidth(1);
    line->setStyleSheet("background:#E3E5E8;border:none;");
    return line;
}

/// 统计数字块（草图右栏的 2×2）。valueOut 回传数值标签，供后续刷新。
QFrame* makeTile(const QString& caption, QLabel** valueOut) {
    auto* tile = new QFrame();
    tile->setObjectName("tile");
    auto* layout = new QVBoxLayout(tile);
    layout->setContentsMargins(8, 6, 8, 6);
    layout->setSpacing(2);
    auto* captionLabel = new QLabel(caption);
    captionLabel->setObjectName("tileCaption");
    auto* valueLabel = new QLabel("—");
    valueLabel->setObjectName("tileValue");
    layout->addWidget(captionLabel);
    layout->addWidget(valueLabel);
    *valueOut = valueLabel;
    return tile;
}

}  // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    worker_ = new SessionWorker(this);
    buildUi();
    connectSignals();
    setSessionActive(false);
    setHandshakeStep(0);
    updateStatusBar();
    appendLog("欢迎使用 SecureTransfer 图形界面。请选择角色并点击“连接”。");
}

MainWindow::~MainWindow() = default;

// ---------------------------------------------------------------------------
//  界面搭建
// ---------------------------------------------------------------------------

void MainWindow::buildUi() {
    setWindowTitle("SecureTransfer — 安全的信息传输套件");
    // 默认尺寸要能放进 1366×768 这类笔记本屏幕（否则系统会把窗口压缩，
    // 控件被挤到"文字只显示一半"）；同时给出最小尺寸，保证再小也不会压变形。
    resize(1180, 720);
    setMinimumSize(1040, 660);

    auto* central = new QWidget();
    central->setObjectName("centralArea");
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // ---- 顶部标题条 ----
    auto* header = new QFrame();
    header->setObjectName("headerBar");
    auto* headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(14, 8, 14, 8);
    auto* appTitle = new QLabel("SecureTransfer");
    appTitle->setObjectName("appTitle");
    statusText_ = new QLabel("未连接");
    statusText_->setObjectName("statusText");
    statusDot_ = makeDot("#8B949E");
    headerLayout->addWidget(appTitle);
    headerLayout->addStretch(1);
    headerLayout->addWidget(statusDot_);
    headerLayout->addWidget(statusText_);
    root->addWidget(header);

    // ---- 工具条 ----
    auto* toolbar = new QFrame();
    toolbar->setObjectName("toolBar");
    auto* toolLayout = new QHBoxLayout(toolbar);
    toolLayout->setContentsMargins(14, 6, 14, 6);
    toolLayout->setSpacing(6);
    startButton_ = new QPushButton("连接");
    startButton_->setObjectName("primary");
    stopButton_ = new QPushButton("断开");
    stopButton_->setObjectName("danger");
    pickFileButton_ = new QPushButton("发送文件");
    pickImageButton_ = new QPushButton("发送图像");
    whoamiButton_ = new QPushButton("查询身份");
    viewLogButton_ = new QPushButton("审计日志");
    advancedButton_ = new QPushButton("高级设置…");
    toolLayout->addWidget(startButton_);
    toolLayout->addWidget(stopButton_);
    toolLayout->addWidget(makeSeparator());
    toolLayout->addWidget(pickFileButton_);
    toolLayout->addWidget(pickImageButton_);
    toolLayout->addWidget(whoamiButton_);
    toolLayout->addWidget(viewLogButton_);
    toolLayout->addStretch(1);
    toolLayout->addWidget(advancedButton_);
    root->addWidget(toolbar);

    // ---- 三栏主体（可拖拽） ----
    auto* splitter = new QSplitter(Qt::Horizontal);
    splitter->setChildrenCollapsible(false);
    splitter->addWidget(buildLeftColumn());
    splitter->addWidget(buildCenterColumn());
    splitter->addWidget(buildRightColumn());
    splitter->setStretchFactor(0, 0);
    splitter->setStretchFactor(1, 1);
    splitter->setStretchFactor(2, 0);
    splitter->setSizes({240, 660, 250});
    // 草图里三栏外面有一圈留白；这里用一层 body 容器补上（标题条/工具条仍贴边）
    auto* body = new QWidget();
    auto* bodyLayout = new QVBoxLayout(body);
    bodyLayout->setContentsMargins(10, 10, 10, 10);
    bodyLayout->setSpacing(0);
    bodyLayout->addWidget(splitter);
    root->addWidget(body, 1);

    setCentralWidget(central);

    // ---- 状态栏 ----
    statusBarInfo_ = new QLabel();
    statusReadyLabel_ = new QLabel("就绪");
    statusReadyLabel_->setObjectName("statusText");
    statusBar()->addWidget(statusBarInfo_);
    statusBar()->addPermanentWidget(statusReadyLabel_);

    // 高级设置对话框在启动时就建好（隐藏），这样 collectConfig() 随时能读到参数。
    buildAdvancedDialog();

    // 防回归（计划 R1）：所有输入类控件的"最小高度 = sizeHint 高度"，
    // 空间不足时布局最多把它们压到最合适尺寸，不会压成"文字只剩半行"。
    const std::initializer_list<QWidget*> pinned = {
        roleBox_,        hostEdit_,      portSpin_,       localIdBox_,       startButton_,
        stopButton_,     inputEdit_,     sendButton_,     pickFileButton_,   pickImageButton_,
        whoamiButton_,   viewLogButton_, tamperButton_,   replayButton_,     advancedButton_,
        exportLogButton_, logLevelBox_,  logFilterEdit_,  peerSummaryLabel_, pathSummaryLabel_,
    };
    for (QWidget* widget : pinned) {
        if (widget != nullptr) {
            widget->setMinimumHeight(widget->sizeHint().height());
        }
    }
}

QWidget* MainWindow::buildLeftColumn() {
    auto* column = new QWidget();
    auto* layout = new QVBoxLayout(column);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);

    // 1) 会话状态
    auto* stateBox = new QGroupBox("会话状态");
    auto* stateLayout = new QVBoxLayout(stateBox);
    stateLayout->setSpacing(6);
    statusLabel_ = new QLabel("● 未连接");
    statusLabel_->setStyleSheet("font-weight:600;color:#8B949E;");
    sessionInfoLabel_ = new QLabel("会话信息：—");
    sessionInfoLabel_->setWordWrap(true);
    roleInfoLabel_ = new QLabel("角色与权限：—");
    roleInfoLabel_->setWordWrap(true);
    stateLayout->addWidget(statusLabel_);
    stateLayout->addWidget(sessionInfoLabel_);
    stateLayout->addWidget(roleInfoLabel_);
    layout->addWidget(stateBox);

    // 2) 握手进度（7 步）
    auto* handshakeBox = new QGroupBox("握手进度");
    auto* handshakeLayout = new QVBoxLayout(handshakeBox);
    handshakeLayout->setSpacing(3);
    for (int i = 0; i < kHandshakeSteps; ++i) {
        handshakeDots_[i] = new QLabel();
        handshakeLayout->addWidget(handshakeDots_[i]);
    }
    handshakeHint_ = new QLabel();
    handshakeHint_->setObjectName("tileCaption");
    handshakeLayout->addWidget(handshakeHint_);
    layout->addWidget(handshakeBox);

    // 3) 连接设置（主界面只留最常用的四项；其余在"高级设置"里）
    auto* connBox = new QGroupBox("连接设置");
    auto* connLayout = new QVBoxLayout(connBox);
    connLayout->setSpacing(6);
    auto* form = new QFormLayout();
    // 长标签单独占一行，而不是把整个标签列撑宽（否则左栏会被撑出滚动条）
    form->setRowWrapPolicy(QFormLayout::WrapLongRows);
    form->setContentsMargins(0, 0, 0, 0);
    form->setSpacing(6);
    roleBox_ = new QComboBox();
    roleBox_->addItems({"客户端（Alice）", "服务端（Bob）"});
    hostEdit_ = new QLineEdit("127.0.0.1");
    portSpin_ = new QSpinBox();
    portSpin_->setRange(1, 65535);
    portSpin_->setValue(9000);
    localIdBox_ = new QComboBox();
    localIdBox_->setEditable(true);
    localIdBox_->addItems({"alice", "eve", "mallory", "bob"});
    form->addRow("角色", roleBox_);
    form->addRow("对端地址", hostEdit_);
    form->addRow("端口", portSpin_);
    form->addRow("本端身份", localIdBox_);
    connLayout->addLayout(form);
    peerSummaryLabel_ = new QLabel("—");
    peerSummaryLabel_->setWordWrap(true);
    peerSummaryLabel_->setStyleSheet("color:#59636E;font-size:8pt;");
    pathSummaryLabel_ = new QLabel("—");
    pathSummaryLabel_->setWordWrap(true);
    pathSummaryLabel_->setStyleSheet("color:#59636E;font-size:8pt;");
    connLayout->addWidget(peerSummaryLabel_);
    connLayout->addWidget(pathSummaryLabel_);
    layout->addWidget(connBox);
    layout->addStretch(1);

    // 左栏放进滚动区：屏幕/窗口不够高时出现滚动条，而不是把控件压扁
    leftScroll_ = new QScrollArea();
    leftScroll_->setObjectName("cardScroll");
    leftScroll_->setWidget(column);
    leftScroll_->setWidgetResizable(true);
    leftScroll_->setFrameShape(QFrame::NoFrame);
    // 内容比可视区宽时**必须**能滚动，否则文字会被静默裁掉
    leftScroll_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    leftScroll_->setMinimumWidth(210);
    leftScroll_->setMaximumWidth(460);
    return leftScroll_;
}

QWidget* MainWindow::buildCenterColumn() {
    auto* column = new QWidget();
    auto* layout = new QVBoxLayout(column);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);

    // 1) 短消息
    auto* messageBox = new QGroupBox("短消息（全程加密 + 完整性保护）");
    auto* messageLayout = new QVBoxLayout(messageBox);
    messageLayout->setSpacing(6);
    historyEdit_ = new QTextEdit();
    historyEdit_->setObjectName("historyView");
    historyEdit_->setReadOnly(true);
    historyEdit_->setMinimumHeight(120);
    // 文本区会随内容增长抬高 sizeHint，进而把整列撑大、把上面的控件压变形；
    // 让它在垂直方向"忽略 sizeHint"，高度完全由布局按剩余空间分配。
    historyEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
    inputEdit_ = new QLineEdit();
    inputEdit_->setPlaceholderText("输入要安全传输的短消息，回车或点击“发送”");
    sendButton_ = new QPushButton("发送");
    sendButton_->setObjectName("primary");
    auto* sendRow = new QHBoxLayout();
    sendRow->setSpacing(6);
    sendRow->addWidget(inputEdit_, 1);
    sendRow->addWidget(sendButton_);
    messageLayout->addWidget(historyEdit_, 1);
    messageLayout->addLayout(sendRow);
    layout->addWidget(messageBox, 3);

    // 2) 文件 / 图像传输
    auto* transferBox = new QGroupBox("文件 / 图像传输（自动分块 + 整文件 CRC32 校验）");
    auto* transferLayout = new QVBoxLayout(transferBox);
    transferLayout->setSpacing(6);
    auto* pickRow = new QHBoxLayout();
    pickRow->setSpacing(6);
    pickFileButton_ = new QPushButton("选择文件…");
    pickImageButton_ = new QPushButton("选择图像…");
    pickRow->addWidget(pickFileButton_);
    pickRow->addWidget(pickImageButton_);
    pickRow->addStretch(1);
    progressBar_ = new QProgressBar();
    progressBar_->setRange(0, 100);
    progressBar_->setValue(0);
    transferLabel_ = new QLabel("尚未传输文件");
    transferLabel_->setWordWrap(true);
    transferLayout->addLayout(pickRow);
    transferLayout->addWidget(progressBar_);
    transferLayout->addWidget(transferLabel_);
    layout->addWidget(transferBox, 2);

    // 3) Eve 攻击演示（三段式：动作 → 拦截关卡 → 结果）
    auto* attackBox = new QGroupBox("Eve 攻击演示（验证完整性保护与防重放）");
    auto* attackLayout = new QVBoxLayout(attackBox);
    attackLayout->setSpacing(6);
    auto* attackRow = new QHBoxLayout();
    attackRow->setSpacing(6);
    tamperButton_ = new QPushButton("篡改上一个数据包并重发");
    replayButton_ = new QPushButton("原样重放上一个数据包");
    attackRow->addWidget(tamperButton_);
    attackRow->addWidget(replayButton_);
    attackRow->addStretch(1);
    attackResultLabel_ = new QLabel(
        "尚未进行攻击演示。点击上方按钮后，本端构造攻击包并重发，由对端判定后回执拦截关卡。");
    attackResultLabel_->setWordWrap(true);
    attackResultLabel_->setStyleSheet("color:#59636E;");
    attackLayout->addLayout(attackRow);
    attackLayout->addWidget(attackResultLabel_);
    layout->addWidget(attackBox);
    return column;
}

QWidget* MainWindow::buildRightColumn() {
    auto* column = new QWidget();
    auto* layout = new QVBoxLayout(column);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);

    // 统计数字块 2×2
    auto* statsGrid = new QGridLayout();
    statsGrid->setSpacing(6);
    statsGrid->addWidget(makeTile("收包", &tileRecv_), 0, 0);
    statsGrid->addWidget(makeTile("发包", &tileSent_), 0, 1);
    statsGrid->addWidget(makeTile("拒绝", &tileReject_), 1, 0);
    statsGrid->addWidget(makeTile("吞吐 MB/s", &tileThroughput_), 1, 1);
    layout->addLayout(statsGrid);

    // 运行日志：级别下拉 + 关键字过滤 + 导出
    auto* logBox = new QGroupBox("运行日志");
    auto* logLayout = new QVBoxLayout(logBox);
    logLayout->setSpacing(6);
    logLevelBox_ = new QComboBox();
    logLevelBox_->addItems({"全部级别", "信息", "成功", "警告", "错误"});
    exportLogButton_ = new QPushButton("导出");
    auto* filterRow = new QHBoxLayout();
    filterRow->setSpacing(6);
    filterRow->addWidget(logLevelBox_, 1);
    filterRow->addWidget(exportLogButton_);
    logFilterEdit_ = new QLineEdit();
    logFilterEdit_->setPlaceholderText("过滤关键字…");
    logEdit_ = new QPlainTextEdit();
    logEdit_->setObjectName("logView");
    logEdit_->setReadOnly(true);
    logEdit_->setMaximumBlockCount(kMaxLogEntries);
    logEdit_->setMinimumHeight(150);
    logEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
    logLayout->addLayout(filterRow);
    logLayout->addWidget(logFilterEdit_);
    logLayout->addWidget(logEdit_, 1);
    layout->addWidget(logBox, 1);

    column->setMinimumWidth(230);
    return column;
}

void MainWindow::buildAdvancedDialog() {
    advancedDialog_ = new QDialog(this);
    advancedDialog_->setWindowTitle("高级设置（建链参数）");
    advancedDialog_->setMinimumWidth(480);
    auto* layout = new QVBoxLayout(advancedDialog_);
    layout->setSpacing(8);

    auto* hint =
        new QLabel("这些是建链参数，通常不需要改动；修改后在下一次点击“连接”时生效。",
                   advancedDialog_);
    hint->setWordWrap(true);
    hint->setStyleSheet("color:#59636E;");
    layout->addWidget(hint);

    auto* form = new QFormLayout();
    form->setRowWrapPolicy(QFormLayout::WrapLongRows);
    form->setSpacing(6);
    peerIdEdit_ = new QLineEdit("bob");
    keyFileEdit_ = new QLineEdit(resolvePath("configs/keys.conf", "."));
    policyFileEdit_ = new QLineEdit(resolvePath("configs/access_policy.conf", "."));
    outDirEdit_ = new QLineEdit(resolvePath("experiment_data/received", ".."));
    accessLogEdit_ = new QLineEdit(resolvePath("experiment_data/access_log.txt", ".."));
    form->addRow("对端身份（握手校验）", peerIdEdit_);
    form->addRow("密钥配置", keyFileEdit_);
    form->addRow("访问策略", policyFileEdit_);
    form->addRow("接收目录", outDirEdit_);
    form->addRow("审计日志", accessLogEdit_);
    layout->addLayout(form);

    auto* buttonRow = new QHBoxLayout();
    buttonRow->addStretch(1);
    auto* closeButton = new QPushButton("关闭", advancedDialog_);
    closeButton->setObjectName("primary");
    buttonRow->addWidget(closeButton);
    layout->addLayout(buttonRow);
    connect(closeButton, &QPushButton::clicked, advancedDialog_, &QDialog::accept);

    const std::initializer_list<QWidget*> inputs = {peerIdEdit_, keyFileEdit_, policyFileEdit_,
                                                    outDirEdit_, accessLogEdit_, closeButton};
    for (QWidget* widget : inputs) {
        widget->setMinimumHeight(widget->sizeHint().height());
    }
}

void MainWindow::connectSignals() {
    // 工作线程 → 界面
    connect(worker_, &SessionWorker::logLine, this, &MainWindow::appendLog);
    connect(worker_, &SessionWorker::stateChanged, this, &MainWindow::onStateChanged);
    connect(worker_, &SessionWorker::sessionEstablished, this, &MainWindow::onEstablished);
    connect(worker_, &SessionWorker::messageReceived, this, &MainWindow::onMessageReceived);
    connect(worker_, &SessionWorker::transferProgress, this, &MainWindow::onTransferProgress);
    connect(worker_, &SessionWorker::transferFinished, this, &MainWindow::onTransferFinished);
    connect(worker_, &SessionWorker::statsUpdated, this, &MainWindow::onStatsUpdated);
    connect(worker_, &SessionWorker::sessionStopped, this, &MainWindow::onSessionStopped);
    connect(worker_, &SessionWorker::attackDetected, this, &MainWindow::onAttackDetected);
    connect(worker_, &SessionWorker::handshakeStep, this, &MainWindow::setHandshakeStep);

    // 界面控件
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
    connect(advancedButton_, &QPushButton::clicked, this, &MainWindow::onAdvancedSettings);
    connect(exportLogButton_, &QPushButton::clicked, this, &MainWindow::onExportLog);
    connect(logLevelBox_, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &MainWindow::onLogFilterChanged);
    connect(logFilterEdit_, &QLineEdit::textChanged, this, &MainWindow::onLogFilterChanged);

    // 状态栏刷新（会话时长）
    sessionTimer_ = new QTimer(this);
    sessionTimer_->setInterval(1000);
    connect(sessionTimer_, &QTimer::timeout, this, &MainWindow::updateStatusBar);
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

void MainWindow::setStatusIndicator(const QString& text, const QColor& color) {
    statusText_->setText(text);
    statusDot_->setStyleSheet(QString("background:%1;border-radius:4px;").arg(color.name()));
    statusLabel_->setText("● " + text);
    statusLabel_->setStyleSheet(QString("font-weight:600;color:%1;").arg(color.name()));
}

void MainWindow::updateSummaries() {
    const QString peer = peerIdEdit_->text().trimmed();
    peerSummaryLabel_->setText(QString("对端身份：%1").arg(peer.isEmpty() ? "—" : peer));
    const QString key = QFileInfo(keyFileEdit_->text().trimmed()).fileName();
    const QString policy = QFileInfo(policyFileEdit_->text().trimmed()).fileName();
    const QString out = QDir(outDirEdit_->text().trimmed()).dirName();
    pathSummaryLabel_->setText(QString("密钥 %1 ｜ 策略 %2 ｜ 接收 %3")
                                   .arg(key.isEmpty() ? "—" : key)
                                   .arg(policy.isEmpty() ? "—" : policy)
                                   .arg(out.isEmpty() ? "—" : out));
}

void MainWindow::updateStatusBar() {
    QString duration = "—";
    if (sessionStart_.isValid()) {
        const qint64 seconds = sessionStart_.secsTo(QDateTime::currentDateTime());
        const int safe = static_cast<int>(seconds < 0 ? 0 : seconds);
        duration = QTime(0, 0).addSecs(safe).toString("mm:ss");
    }
    statusBarInfo_->setText(QString("端口 %1 ｜ AES-128-CTR + CMAC ｜ 会话时长 %2")
                                .arg(portSpin_->value())
                                .arg(duration));
}

// ---------------------------------------------------------------------------
//  按钮槽函数
// ---------------------------------------------------------------------------

void MainWindow::onRoleChanged() {
    const bool isServer = roleBox_->currentIndex() == 1;
    hostEdit_->setEnabled(!isServer);
    peerIdEdit_->setText(isServer ? "alice" : "bob");
    localIdBox_->setCurrentText(isServer ? "bob" : "alice");
    updateSummaries();
    appendLog(isServer ? "已选择服务端角色（Bob）：点击“连接”后等待对端接入。"
                       : "已选择客户端角色（Alice）：点击“连接”后连接到对端。");
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
    updateSummaries();
    setHandshakeStep(0);
    setStatusIndicator("连接中…", stui::colorWarning());
    statusReadyLabel_->setText("会话进行中");
    appendLog(QString("===== 开始会话：%1，本端 %2，对端 %3，端口 %4 =====")
                  .arg(config.isServer ? "服务端" : "客户端")
                  .arg(config.localId)
                  .arg(config.peerId)
                  .arg(config.port));
    handshakeDone_ = false;
    setSessionActive(true);
    worker_->start(config);
}

void MainWindow::onStopClicked() {
    appendLog("正在结束会话…");
    statusReadyLabel_->setText("正在结束会话…");
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
    const QString path =
        QFileDialog::getOpenFileName(this, "选择要安全传输的文件", lastSendDirectory_);
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
    lastAttackAction_ = "篡改上一个数据包的密文字节并重发";
    attackResultLabel_->setText(
        QString("动作：%1\n拦截关卡：等待对端判定…\n结果：—").arg(lastAttackAction_));
    attackResultLabel_->setStyleSheet("color:#D29922;");
    appendLog("⚠ 触发攻击演示：篡改上一个数据包（对端应拒绝并终止会话）");
    worker_->requestTamper();
}

void MainWindow::onReplay() {
    lastAttackAction_ = "原样重放上一个数据包";
    attackResultLabel_->setText(
        QString("动作：%1\n拦截关卡：等待对端判定…\n结果：—").arg(lastAttackAction_));
    attackResultLabel_->setStyleSheet("color:#D29922;");
    appendLog("⚠ 触发攻击演示：重放上一个数据包（对端应判定为重放）");
    worker_->requestReplay();
}

void MainWindow::onAdvancedSettings() {
    advancedDialog_->exec();
    updateSummaries();
    appendLog("已关闭高级设置（建链参数在下一次“连接”时生效）");
}

// ---------------------------------------------------------------------------
//  工作线程信号与界面内部逻辑
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
    appendLogWithLevel(classifyLogLevel(text), text);
}

bool MainWindow::logPassesFilter(const LogEntry& entry) const {
    const int wanted = logLevelBox_->currentIndex();
    if (wanted > 0 && entry.level != wanted - 1) {
        return false;
    }
    const QString keyword = logFilterEdit_->text().trimmed();
    if (!keyword.isEmpty() && !entry.text.contains(keyword, Qt::CaseInsensitive)) {
        return false;
    }
    return true;
}

void MainWindow::renderLog() {
    logEdit_->clear();
    QTextCursor cursor(logEdit_->document());
    for (const LogEntry& entry : logEntries_) {
        if (!logPassesFilter(entry)) {
            continue;
        }
        QTextCharFormat format;
        format.setForeground(stui::colorForLevel(static_cast<stui::LogLevel>(entry.level)));
        cursor.setCharFormat(format);
        cursor.insertText(entry.text + "\n");
    }
    logEdit_->moveCursor(QTextCursor::End);
}

void MainWindow::appendLogWithLevel(int level, const QString& text) {
    LogEntry entry;
    entry.level = level;
    entry.text = QString("[%1] %2").arg(stamp()).arg(text);
    logEntries_.append(entry);
    if (logEntries_.size() > kMaxLogEntries) {
        logEntries_.remove(0, logEntries_.size() - kMaxLogEntries);
    }
    if (!logPassesFilter(entry)) {
        return;
    }
    QTextCharFormat format;
    format.setForeground(stui::colorForLevel(static_cast<stui::LogLevel>(level)));
    QTextCursor cursor(logEdit_->document());
    cursor.movePosition(QTextCursor::End);
    cursor.setCharFormat(format);
    cursor.insertText(entry.text + "\n");
    logEdit_->moveCursor(QTextCursor::End);
    logEdit_->ensureCursorVisible();
}

void MainWindow::onLogFilterChanged() {
    renderLog();
}

void MainWindow::onExportLog() {
    if (logEntries_.isEmpty()) {
        appendLog("[WARN] 当前没有可导出的日志");
        return;
    }
    const QString directory = resolvePath("experiment_data", "..");
    const QString suggested = QDir(directory).filePath(
        QString("ui_log_%1.txt").arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")));
    const QString path =
        QFileDialog::getSaveFileName(this, "导出运行日志", suggested, "文本文件 (*.txt)");
    if (path.isEmpty()) {
        appendLog("已取消导出运行日志");
        return;
    }
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        appendLog("[ERROR] 无法写入日志文件：" + path);
        return;
    }
    QTextStream stream(&file);
    stream.setCodec("UTF-8");
    for (const LogEntry& entry : logEntries_) {
        stream << logLevelName(entry.level) << '\t' << entry.text << '\n';
    }
    file.close();
    appendLog("已导出运行日志：" + path);
}

void MainWindow::setHandshakeStep(int step) {
    currentHandshakeStep_ = qBound(0, step, kHandshakeSteps);
    for (int i = 0; i < kHandshakeSteps; ++i) {
        const bool done = i < currentHandshakeStep_;
        handshakeDots_[i]->setText(
            QString("%1 %2").arg(done ? "●" : "○", QString::fromUtf8(kHandshakeStepNames[i])));
        handshakeDots_[i]->setStyleSheet(done ? "color:#12A150;" : "color:#8B949E;");
    }
    handshakeHint_->setText(
        QString("已完成 %1 / %2 步").arg(currentHandshakeStep_).arg(kHandshakeSteps));
}

void MainWindow::onStateChanged(const QString& state) {
    if (state.contains("ESTABLISHED")) {
        setStatusIndicator(state, stui::colorSuccess());
    } else if (state.contains("失败")) {
        setStatusIndicator(state, stui::colorDanger());
    } else {
        setStatusIndicator(state, stui::colorWarning());
    }
    appendLog(state);
}

void MainWindow::onEstablished(const QString& summary) {
    setStatusIndicator("安全会话已建立（ESTABLISHED）", stui::colorSuccess());
    statusReadyLabel_->setText("就绪");
    // worker 的摘要分两行：第一行是会话信息（SessionId / Nonce），第二行是角色与权限。
    const QStringList lines = summary.split('\n');
    sessionInfoLabel_->setText("会话信息：" + lines.value(0));
    if (lines.size() > 1) {
        roleInfoLabel_->setText("角色与权限：" + lines.mid(1).join(" "));
    }
    if (!sessionStart_.isValid()) {
        sessionStart_ = QDateTime::currentDateTime();
        sessionTimer_->start();
    }
    updateStatusBar();
    appendLog("会话信息：" + QString(summary).replace('\n', " ｜ "));

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
    updateSummaries();
    updateStatusBar();
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
        std::printf("%-16s %4d x %-4d  minimumHeight=%3d  sizeHintHeight=%3d\n", name, w->width(),
                    w->height(), w->minimumHeight(), w->sizeHint().height());
    };

    std::printf("window           %4d x %-4d  minimum=%d x %d  dpr=%.2f\n", width(), height(),
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
    dump("advancedButton", advancedButton_);
    dump("exportLogButton", exportLogButton_);
    dump("logLevelBox", logLevelBox_);
    dump("logFilterEdit", logFilterEdit_);
    dump("historyEdit", historyEdit_);
    dump("logEdit", logEdit_);
    dump("handshake[0]", handshakeDots_[0]);
    dump("handshake[6]", handshakeDots_[kHandshakeSteps - 1]);

    // 左列是滚动区：如果 viewport 比内容窄，内容就会被裁掉（表现就是"左边几列文字看不到"）
    if (leftScroll_ != nullptr) {
        const QWidget* inner = leftScroll_->widget();
        std::printf("leftScroll       viewport=%d x %d  innerWidget=%d x %d  "
                    "hScroll=%d vScroll=%d  innerMinWidth=%d\n",
                    leftScroll_->viewport()->width(), leftScroll_->viewport()->height(),
                    inner != nullptr ? inner->width() : -1, inner != nullptr ? inner->height() : -1,
                    leftScroll_->horizontalScrollBar()->value(),
                    leftScroll_->verticalScrollBar()->value(),
                    inner != nullptr ? inner->minimumSizeHint().width() : -1);
    }

    // 所有标签：宽度小于 sizeHint 就说明文字被裁（省略号或直接消失）
    for (const QLabel* label : findChildren<QLabel*>()) {
        if (label->isVisible() && !label->text().isEmpty()) {
            std::printf("label  w=%4d  sizeHintW=%4d  text=%s\n", label->width(),
                        label->sizeHint().width(), label->text().left(28).toUtf8().constData());
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
    const bool outgoing = type.startsWith(QString::fromUtf8("我"));
    const QString background = outgoing ? "#E7F0FF" : "#F5F6F8";
    const QString color = outgoing ? "#1F6FEB" : "#1F2328";
    const QString align = outgoing ? "right" : "left";
    const QString html =
        QString("<div style=\"text-align:%1\">"
                "<span style=\"background-color:%2;color:%3;border-radius:8px;"
                "padding:4px 8px;\">%4</span>"
                "<div style=\"font-size:8pt;color:#8B949E;margin-top:2px;\">%5 · %6 字节</div>"
                "</div>")
            .arg(align, background, color, text.toHtmlEscaped())
            .arg(type)
            .arg(bytes);
    historyEdit_->append(html);
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
    const QString recv = statToken(summary, "recv");
    const QString sent = statToken(summary, "sent");
    tileRecv_->setText(recv.isEmpty() ? "—" : recv);
    tileSent_->setText(sent.isEmpty() ? "—" : sent);

    // 拒绝计数在摘要里是一个 "format/replay/mac/state" 四元组，这里求和。
    int rejected = 0;
    const QString rejectToken = statToken(summary, "reject(format/replay/mac/state)");
    for (const QString& part : rejectToken.split('/')) {
        rejected += part.toInt();
    }
    tileReject_->setText(QString::number(rejected));

    // 吞吐：累计字节 / 会话时长（只有会话建立后才算）
    qint64 totalBytes = 0;
    for (const QString& part : statToken(summary, "bytes").split('/')) {
        totalBytes += part.toLongLong();
    }
    if (sessionStart_.isValid()) {
        const qint64 seconds = sessionStart_.secsTo(QDateTime::currentDateTime());
        if (seconds > 0) {
            tileThroughput_->setText(
                QString::number(static_cast<double>(totalBytes) / seconds / 1.0e6, 'f', 1));
        } else if (totalBytes > 0) {
            tileThroughput_->setText("—");
        }
    }
}

void MainWindow::onSessionStopped(const QString& reason) {
    setStatusIndicator("会话已结束", stui::colorDanger());
    sessionTimer_->stop();
    sessionStart_ = QDateTime();
    updateStatusBar();
    statusReadyLabel_->setText("就绪");
    appendLog("会话结束：" + reason);
    setSessionActive(false);
}

void MainWindow::onAttackDetected(const QString& gate, const QString& reason) {
    // Eve 面板三段式：动作 → 拦截关卡 → 结果
    attackResultLabel_->setText(
        QString("动作：%1\n拦截关卡：%2\n结果：对端已终止会话并回执（会话需重新建立才能继续演示）"
                "\n原因：%3")
            .arg(lastAttackAction_.isEmpty() ? "攻击包" : lastAttackAction_)
            .arg(gate)
            .arg(reason));
    attackResultLabel_->setStyleSheet("color:#D1242F;");
    appendLog(QString("【攻击判定】对端被拦在第 %1 关").arg(gate));
    appendLog(QString("            原因：%1").arg(reason));
}
