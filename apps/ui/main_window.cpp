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

#include <QAbstractItemView>
#include <QAbstractButton>
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
#include <QHeaderView>
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
#include <QTableWidget>
#include <QTabWidget>
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

/// 内核 RejectGate 的 8 道关卡（顺序与 include/security/session.h 一致）。
const char* const kGateNames[kRejectGates] = {
    "① 帧", "② 格式", "③ SessionId", "④ 方向", "⑤ 类型", "⑥ 重放", "⑦ CMAC", "⑧ 状态机",
};
const char* const kGateCircled[kRejectGates] = {"①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧"};

/// 把内核给的中文关卡名（例如 "⑦ CMAC 完整性校验失败"）映射成 1..8；识别不了返回 0。
int gateIndexOf(const QString& gateText) {
    for (int i = 0; i < kRejectGates; ++i) {
        if (gateText.contains(QString::fromUtf8(kGateCircled[i]))) {
            return i + 1;
        }
    }
    return 0;
}

QString chipStyle(bool hit) {
    if (hit) {
        return QStringLiteral(
            "background:#FDECEE;color:#D1242F;border:1px solid #F1B5B9;border-radius:5px;"
            "padding:3px 4px;font-weight:600;");
    }
    return QStringLiteral(
        "background:#F5F6F8;color:#8B949E;border:1px solid #E3E5E8;border-radius:5px;"
        "padding:3px 4px;");
}

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

/// 把页签内容包进滚动区。
///
/// 为什么必须这样：窗口高度受屏幕限制（本机 200% 缩放，逻辑桌面只有约 1080×720），
/// 而"中间人链路"页的内容最小高度就有 282px —— 直接放进 QTabWidget 的话，
/// 空间不够时 Qt 会把子控件压到最小高度以下，文字被纵向裁掉、内容看不见
/// （用户报的"文字压缩且显示不全"就是这个）。包一层滚动区之后，
/// 空间不够时出现滚动条，而不是丢内容。
QWidget* wrapInScrollArea(QWidget* page) {
    auto* area = new QScrollArea();
    area->setWidgetResizable(true);
    area->setFrameShape(QFrame::NoFrame);
    area->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    area->setWidget(page);
    return area;
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
        roleBox_,         hostEdit_,          portSpin_,         localIdBox_,
        startButton_,     stopButton_,        inputEdit_,        sendButton_,
        pickFileButton_,  pickImageButton_,   whoamiButton_,     viewLogButton_,
        advancedButton_,  exportLogButton_,   logLevelBox_,      logFilterEdit_,
        peerSummaryLabel_, pathSummaryLabel_, attackSourceBox_,  attackKindBox_,
        attackTargetBox_, attackIndexSpin_,   launchAttackButton_, reconnectButton_,
        scenarioButton_,
        relayListenSpin_, relayTargetSpin_,   relayStartButton_, relayStopButton_,
        exportHistoryButton_,
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
    roleBox_->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    roleBox_->addItems({"客户端（Alice）", "服务端（Bob）"});
    hostEdit_ = new QLineEdit("127.0.0.1");
    portSpin_ = new QSpinBox();
    portSpin_->setRange(1, 65535);
    portSpin_->setValue(9000);
    localIdBox_ = new QComboBox();
    localIdBox_->setEditable(true);
    localIdBox_->setSizeAdjustPolicy(QComboBox::AdjustToContents);
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
    // 1) 短消息
    auto* messageBox = new QGroupBox("短消息（全程加密 + 完整性保护）");
    auto* messageLayout = new QVBoxLayout(messageBox);
    messageLayout->setSpacing(6);
    historyEdit_ = new QTextEdit();
    historyEdit_->setObjectName("historyView");
    historyEdit_->setReadOnly(true);
    historyEdit_->setMinimumHeight(110);
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

    // 3) Eve 攻击演示（三页签：攻击 / 中间人 / 历史）
    // 中栏三张卡片放进一个可拖拽的垂直分栏：Eve 面板内容多，用户想细看时自己拖大即可，
    // 不像固定布局那样必须把窗口拉高。
    auto* column = new QSplitter(Qt::Vertical);
    column->setChildrenCollapsible(false);
    column->addWidget(messageBox);
    column->addWidget(transferBox);
    column->addWidget(buildEveCard());
    column->setStretchFactor(0, 3);
    column->setStretchFactor(1, 1);
    column->setStretchFactor(2, 2);
    column->setSizes({230, 120, 250});
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
    logLevelBox_->setSizeAdjustPolicy(QComboBox::AdjustToContents);
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

// ---------------------------------------------------------------------------
//  Eve 攻击卡片：三页签（攻击演示 / 中间人链路 / 攻击历史）
// ---------------------------------------------------------------------------

QWidget* MainWindow::buildEveCard() {
    auto* card = new QGroupBox("Eve 攻击演示（链路中间人 + 内核拦截关卡）");
    auto* cardLayout = new QVBoxLayout(card);
    cardLayout->setSpacing(6);
    eveTabs_ = new QTabWidget();
    cardLayout->addWidget(eveTabs_);

    // ======================= 页签 1：攻击演示 =======================
    auto* attackTab = new QWidget();
    auto* attackLayout = new QVBoxLayout(attackTab);
    attackLayout->setSpacing(6);

    auto* pickRow = new QHBoxLayout();
    pickRow->setSpacing(6);
    // 下拉框一律"按内容自适应"：默认的 sizeHint 会按最长那一项要宽度，
    // 在窄列里会把整行撑爆、把旁边的文字压掉（上一轮自检量到过 58px < 需要 60px）。
    attackSourceBox_ = new QComboBox();
    attackSourceBox_->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    attackSourceBox_->addItem("中间人", 0);
    attackSourceBox_->addItem("端点视角", 1);
    attackSourceBox_->setToolTip("中间人：攻击由独立的 eve 中继进程在链路上执行\n"
                                 "端点视角：由本端进程自己构造攻击包（只能打最近一个已发送的包）");
    attackKindBox_ = new QComboBox();
    attackKindBox_->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    // 目标不再是写死的"第 5/6/7 个包"，而是"打哪一类包"
    attackTargetBox_ = new QComboBox();
    attackTargetBox_->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    attackTargetBox_->addItem("下一个包", 0);
    attackTargetBox_->addItem("下一条短消息", 1);
    attackTargetBox_->addItem("下一个文件块", 2);
    attackTargetBox_->addItem("最近一条短消息", 3);
    attackTargetBox_->addItem("第 N 条短消息", 4);
    attackTargetBox_->addItem("指定第 N 个包（含握手）", 5);
    attackTargetBox_->setToolTip(
        "「最近一条短消息」＝ 捕获-篡改/重发：拿刚才那条再打一次，不用等新包\n"
        "「第 N 条短消息」只数 DATA（不受 4 个握手包干扰）\n"
        "「指定第 N 个包」从连接建立起算，含 4 个握手包");
    attackIndexSpin_ = new QSpinBox();
    attackIndexSpin_->setRange(1, 999);
    attackIndexSpin_->setValue(1);
    attackIndexSpin_->setEnabled(false);
    attackIndexSpin_->setMaximumWidth(80);
    launchAttackButton_ = new QPushButton("发起攻击");
    launchAttackButton_->setObjectName("danger");
    reconnectButton_ = new QPushButton("重新建立会话");
    reconnectButton_->setObjectName("primary");
    scenarioButton_ = new QPushButton("一键攻击剧本");

    pickRow->addWidget(new QLabel("来源"));
    pickRow->addWidget(attackSourceBox_);
    pickRow->addWidget(new QLabel("方式"));
    pickRow->addWidget(attackKindBox_);
    pickRow->addWidget(new QLabel("目标"));
    pickRow->addWidget(attackTargetBox_, 1);
    attackLayout->addLayout(pickRow);

    // 操作放第二行：一行塞不下时 Qt 会把控件压到文字显示不全（上一轮的教训）
    auto* actionRow = new QHBoxLayout();
    actionRow->setSpacing(6);
    actionRow->addWidget(new QLabel("序号"));
    actionRow->addWidget(attackIndexSpin_);
    actionRow->addWidget(launchAttackButton_);
    actionRow->addWidget(reconnectButton_);
    actionRow->addWidget(scenarioButton_);
    actionRow->addStretch(1);
    attackLayout->addLayout(actionRow);

    // 目标语义说明：序号到底怎么数、现在轮到第几个、点了之后在等什么
    attackTargetHint_ = new QLabel();
    attackTargetHint_->setWordWrap(true);
    attackTargetHint_->setStyleSheet("color:#59636E;font-size:8pt;");
    attackLayout->addWidget(attackTargetHint_);

    // 8 关流水线：命中哪一关就高亮哪一关（数据来自内核 RejectGate）
    auto* gateRow = new QHBoxLayout();
    gateRow->setSpacing(4);
    for (int i = 0; i < kRejectGates; ++i) {
        gateChips_[i] = new QLabel(QString::fromUtf8(kGateNames[i]));
        gateChips_[i]->setAlignment(Qt::AlignCenter);
        gateChips_[i]->setStyleSheet(chipStyle(false));
        gateRow->addWidget(gateChips_[i]);
    }
    attackLayout->addLayout(gateRow);

    attackResultLabel_ = new QLabel(
        "中间人模式：先把链路切到 Eve 中继（见「中间人链路」页签），再点「发起攻击」。\n"
        "端点模式：由本端进程直接构造攻击包，只能打最近一个已发送的包。");
    attackResultLabel_->setWordWrap(true);
    attackResultLabel_->setStyleSheet("color:#59636E;");
    attackLayout->addWidget(attackResultLabel_);

    // 攻击者视角的边界：Eve 只能确认"注入了"，判定结果在受害端手里（这是安全属性）
    // 文案压到一行内（完整解释放 tooltip）：换行标签一旦被压成一行高，第二行会被裁掉
    attackerViewLabel_ = new QLabel("Eve 只能确认「已注入」；是否被拦由受害端掌握，不会回传。");
    attackerViewLabel_->setWordWrap(true);
    attackerViewLabel_->setStyleSheet("color:#8B949E;font-size:8pt;");
    attackerViewLabel_->setToolTip(
        "攻击者视角的边界：中继只能确认把包注入到了链路；\n"
        "对端是否接受、是否被 CMAC / 防重放拦下，判定发生在受害端进程内部，\n"
        "攻击者拿不到结果 —— 否则就成了可被二分利用的 oracle。");
    attackLayout->addWidget(attackerViewLabel_);
    attackLayout->addStretch(1);
    eveTabs_->addTab(wrapInScrollArea(attackTab), "攻击演示");

    // ======================= 页签 2：中间人链路 =======================
    auto* relayTab = new QWidget();
    auto* relayLayout = new QVBoxLayout(relayTab);
    relayLayout->setSpacing(6);

    auto* relayRow = new QHBoxLayout();
    relayRow->setSpacing(6);
    relayListenSpin_ = new QSpinBox();
    relayListenSpin_->setRange(1, 65535);
    relayListenSpin_->setValue(9400);
    relayListenSpin_->setMaximumWidth(84);
    relayTargetSpin_ = new QSpinBox();
    relayTargetSpin_->setRange(1, 65535);
    relayTargetSpin_->setValue(9000);
    relayTargetSpin_->setMaximumWidth(84);
    relayStartButton_ = new QPushButton("启动中继");
    relayStartButton_->setObjectName("primary");
    relayStopButton_ = new QPushButton("停止中继");
    relayRow->addWidget(new QLabel("监听"));
    relayRow->addWidget(relayListenSpin_);
    relayRow->addWidget(new QLabel("转发到"));
    relayRow->addWidget(relayTargetSpin_);
    relayRow->addWidget(relayStartButton_);
    relayRow->addWidget(relayStopButton_);
    relayRow->addStretch(1);
    relayLayout->addLayout(relayRow);

    relayTopologyLabel_ = new QLabel("链路：Alice（本端）→ Eve（本机中继）→ Bob（真实服务端）");
    relayTopologyLabel_->setWordWrap(true);
    relayTopologyLabel_->setStyleSheet("color:#59636E;");
    relayStateLabel_ = new QLabel("中继状态：未启动");
    relayStateLabel_->setWordWrap(true);
    relayCounterLabel_ = new QLabel("转发 0 ｜ 篡改 0 ｜ 丢弃 0 ｜ 延迟 0 ｜ 重放 0");
    relayCounterLabel_->setStyleSheet("color:#59636E;");
    relayProgressLabel_ = new QLabel("链路已转发：C2S 0 个 ｜ S2C 0 个");
    relayProgressLabel_->setStyleSheet("color:#59636E;");
    relayLayout->addWidget(relayTopologyLabel_);
    relayLayout->addWidget(relayStateLabel_);
    relayLayout->addWidget(relayProgressLabel_);
    relayLayout->addWidget(relayCounterLabel_);

    packetInspectEdit_ = new QPlainTextEdit();
    packetInspectEdit_->setReadOnly(true);
    packetInspectEdit_->setMaximumBlockCount(400);
    packetInspectEdit_->setMinimumHeight(48);
    // 与 historyEdit_/logEdit_ 同理：文本框不要用它那 192px 的 sizeHint 去挤别的卡片，
    // 高度完全交给布局（配合上面的最小高度，既不会被压没，也不会抢空间）。
    packetInspectEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
    packetInspectEdit_->setPlaceholderText(
        "数据包检查器：这里显示中继抓到的每个包（Eve 视角，只有密文）");
    relayLayout->addWidget(packetInspectEdit_, 2);

    auto* visibility = new QLabel(
        "Eve 能看到：TCP 帧、密文、Nonce、Sequence、SessionId、CMAC；"
        "看不到：明文、K_session、K_master");
    visibility->setWordWrap(true);
    visibility->setStyleSheet("color:#59636E;font-size:8pt;");
    relayLayout->addWidget(visibility);

    relayLogEdit_ = new QPlainTextEdit();
    relayLogEdit_->setReadOnly(true);
    relayLogEdit_->setMaximumBlockCount(400);
    relayLogEdit_->setMinimumHeight(36);
    relayLogEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
    relayLogEdit_->setPlaceholderText("中继日志：转发 / 篡改 / 丢弃 / 延迟 / 重放");
    relayLayout->addWidget(relayLogEdit_, 1);
    eveTabs_->addTab(wrapInScrollArea(relayTab), "中间人链路");

    // ======================= 页签 3：攻击历史 =======================
    auto* historyTab = new QWidget();
    auto* historyLayout = new QVBoxLayout(historyTab);
    historyLayout->setSpacing(6);
    attackHistory_ = new QTableWidget(0, 5);
    attackHistory_->setHorizontalHeaderLabels({"时间", "来源", "方式", "拦截关卡", "结果"});
    attackHistory_->horizontalHeader()->setStretchLastSection(true);
    attackHistory_->verticalHeader()->setVisible(false);
    attackHistory_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    attackHistory_->setMinimumHeight(64);
    attackHistory_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
    historyLayout->addWidget(attackHistory_, 1);
    auto* historyRow = new QHBoxLayout();
    exportHistoryButton_ = new QPushButton("导出 CSV");
    historyRow->addStretch(1);
    historyRow->addWidget(exportHistoryButton_);
    historyLayout->addLayout(historyRow);
    eveTabs_->addTab(wrapInScrollArea(historyTab), "攻击历史");

    mitm_ = new MitmController(this);
    onAttackSourceChanged();  // 按默认来源（中间人）决定"方式"下拉里有哪些选项
    updateAttackTargetHint();
    return card;
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
    connect(launchAttackButton_, &QPushButton::clicked, this, &MainWindow::onLaunchAttack);
    connect(reconnectButton_, &QPushButton::clicked, this, &MainWindow::onReconnectClicked);
    connect(scenarioButton_, &QPushButton::clicked, this, &MainWindow::onScenarioClicked);
    connect(attackSourceBox_, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &MainWindow::onAttackSourceChanged);
    connect(attackTargetBox_, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &MainWindow::onAttackSourceChanged);
    connect(attackTargetBox_, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &MainWindow::updateAttackTargetHint);
    connect(attackIndexSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this,
            &MainWindow::updateAttackTargetHint);
    connect(relayStartButton_, &QPushButton::clicked, this, &MainWindow::onRelayStart);
    connect(relayStopButton_, &QPushButton::clicked, this, &MainWindow::onRelayStop);
    connect(exportHistoryButton_, &QPushButton::clicked, this, &MainWindow::onExportHistory);

    // 中继进程 → 界面
    connect(mitm_, &MitmController::relayLine, this, &MainWindow::onRelayLog);
    connect(mitm_, &MitmController::relayPacket, this, &MainWindow::onRelayPacket);
    connect(mitm_, &MitmController::relayAttack, this, &MainWindow::onRelayAttack);
    connect(mitm_, &MitmController::relayStats, this, &MainWindow::onRelayStats);
    connect(mitm_, &MitmController::relayState, this, &MainWindow::onRelayState);
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
    reconnectButton_->setEnabled(!active);
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
    // 剧本：会话一建立就进入"下发攻击 + 发探针消息"这一步（不再靠固定延时猜）
    if (scenarioWaitingForSession_) {
        scenarioWaitingForSession_ = false;
        scenarioStep_ = 3;
        QTimer::singleShot(300, this, &MainWindow::runScenarioStep);
    }
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
    relayListenSpin_->setValue(options.relayListen);
    relayTargetSpin_->setValue(options.relayTarget);
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
    bool relayStarted = false;
    if (options.startRelay || options.scenario) {
        relayStarted = startRelayFromUi();
    }
    if (options.scenario) {
        appendLog("命令行指定了 --scenario：自动运行一键攻击剧本");
        onScenarioClicked();
        return;
    }
    if (options.autoStart) {
        appendLog("命令行指定了 --auto：自动开始会话");
        if (relayStarted) {
            // 让中继先把监听端口绑好，再让本端去连（否则可能 connection refused）
            QTimer::singleShot(1500, this, [this]() { onStartClicked(); });
        } else {
            onStartClicked();
        }
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
    dump("launchAttack", launchAttackButton_);
    dump("reconnectBtn", reconnectButton_);
    dump("relayStart", relayStartButton_);
    dump("attackSource", attackSourceBox_);
    dump("attackTarget", attackTargetBox_);
    dump("attackIndexSpin", attackIndexSpin_);
    dump("attackTargetHint", attackTargetHint_);
    dump("relayProgress", relayProgressLabel_);
    dump("gateChip[0]", gateChips_[0]);
    dump("attackerView", attackerViewLabel_);
    dump("packetInspect", packetInspectEdit_);
    dump("attackHistory", attackHistory_);
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
            std::printf("group  w=%4d  h=%4d  x=%4d  sizeHintW=%4d  minH=%4d  %s\n", box->width(),
                        box->height(), box->x(), box->sizeHint().width(), box->minimumHeight(),
                        box->title().toUtf8().constData());
        }
    }

    // ---- 逐页签布局自检 ----------------------------------------------------
    // 为什么要"逐页签"：Qt 不会给不可见的页签排版，隐藏页里控件的 width 是陈旧值，
    // 直接检查会漏报。这里把每个页签轮流切到前台、重新激活布局之后再检查
    // "承载文字的控件"（不换行的 QLabel / 按钮）是否被压得比它自己需要的还窄 ——
    // 那正是"文字压缩、显示不全"的直接原因。
    const auto reportSqueezed = [](const QWidget* root, const QString& where) {
        if (root == nullptr) {
            return;
        }
        const QSize minHint = root->minimumSizeHint();
        const bool tooSmall =
            root->width() < minHint.width() || root->height() < minHint.height();
        std::printf("page %-22s size=%4d x %-4d  最小需求=%4d x %-4d%s\n",
                    where.toUtf8().constData(), root->width(), root->height(), minHint.width(),
                    minHint.height(), tooSmall ? "   <-- 内容放不下" : "");

        int found = 0;
        for (const QWidget* widget : root->findChildren<QWidget*>()) {
            if (!widget->isVisible()) {
                continue;
            }
            QString text;
            int need = 0;
            if (const auto* label = qobject_cast<const QLabel*>(widget)) {
                if (label->text().isEmpty()) {
                    continue;
                }
                text = label->text();
                if (label->wordWrap()) {
                    // 自动换行的标签"变窄"是正常的（会折行），但**高度不够**就是真的被裁了：
                    // Qt 把 wordWrap 标签的最小高度算成一行，布局于是可以把它压到一行高，
                    // 第二行直接看不见 —— 这正是"文字显示不全"的另一种形态。
                    if (label->sizePolicy().hasHeightForWidth()) {
                        const int neededH = label->heightForWidth(label->width());
                        if (neededH > label->height()) {
                            if (found == 0) {
                                std::printf("[SQUEEZED] %s\n", where.toUtf8().constData());
                            }
                            ++found;
                            std::printf("    %-12s h=%4d < 需要 %4d   %s\n", "QLabel(wrap)",
                                        label->height(), neededH,
                                        text.left(26).toUtf8().constData());
                        }
                    }
                    continue;
                }
                need = label->sizeHint().width();
            } else if (const auto* button = qobject_cast<const QAbstractButton*>(widget)) {
                text = button->text();
                need = button->sizeHint().width();
            } else if (const auto* combo = qobject_cast<const QComboBox*>(widget)) {
                // 下拉框统一设了 AdjustToContents，sizeHint 就是"当前这一项需要的宽度"，
                // 因此 width < sizeHint 就等于"Qt 没给够，文字会被省略号吃掉"。
                text = combo->currentText();
                need = combo->sizeHint().width();
            } else {
                continue;
            }
            if (need > 0 && widget->width() < need) {
                if (found == 0) {
                    std::printf("[SQUEEZED] %s\n", where.toUtf8().constData());
                }
                ++found;
                std::printf("    %-12s w=%4d < 需要 %4d   %s\n",
                            widget->metaObject()->className(), widget->width(), need,
                            text.left(30).toUtf8().constData());
            }
        }
        if (found == 0) {
            std::printf("[OK] %s：没有文字被压缩\n", where.toUtf8().constData());
        }
    };

    reportSqueezed(centralWidget(), QStringLiteral("主窗口"));
    for (QTabWidget* tabs : findChildren<QTabWidget*>()) {
        const int original = tabs->currentIndex();
        for (int i = 0; i < tabs->count(); ++i) {
            tabs->setCurrentIndex(i);
            QWidget* page = tabs->currentWidget();
            if (page != nullptr && page->layout() != nullptr) {
                page->layout()->activate();
            }
            QApplication::processEvents();
            reportSqueezed(page, QStringLiteral("页签「%1」").arg(tabs->tabText(i)));
        }
        tabs->setCurrentIndex(original);
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
    highlightRejectGate(gateIndexOf(gate));
    attackResultLabel_->setText(
        QString("动作：%1\n拦截关卡：%2\n结果：对端已终止会话并回执（会话需重新建立才能继续演示）"
                "\n原因：%3")
            .arg(lastAttackAction_.isEmpty() ? "攻击包" : lastAttackAction_)
            .arg(gate)
            .arg(reason));
    attackResultLabel_->setStyleSheet("color:#D1242F;");
    appendAttackHistory("对端判定", lastAttackAction_.isEmpty() ? QStringLiteral("攻击包")
                                                               : lastAttackAction_,
                        "—", gate, "已拦截（会话已终止）");
    appendLog(QString("【攻击判定】对端被拦在第 %1 关").arg(gate));
    appendLog(QString("            原因：%1").arg(reason));
}

// ---------------------------------------------------------------------------
//  Eve 攻击面板：端点视角 / 中间人链路 / 攻击历史
// ---------------------------------------------------------------------------

void MainWindow::onAttackSourceChanged() {
    const bool viaRelay = attackSourceBox_->currentIndex() == 0;
    const QString keep = attackKindBox_->currentText();
    attackKindBox_->blockSignals(true);
    attackKindBox_->clear();
    attackKindBox_->addItem("篡改");
    attackKindBox_->addItem("重放");
    if (viaRelay) {
        attackKindBox_->addItem("丢弃");
        attackKindBox_->addItem("延迟");
    }
    attackKindBox_->blockSignals(false);
    const int index = attackKindBox_->findText(keep);
    attackKindBox_->setCurrentIndex(index >= 0 ? index : 0);
    // 端点视角只能打"最近一个已发送的包"：目标与序号对它没有意义
    attackTargetBox_->setEnabled(viaRelay);
    const int mode = attackTargetBox_->currentData().toInt();
    attackIndexSpin_->setEnabled(viaRelay && (mode == 4 || mode == 5));
    // 切到"第 N …"时，默认填"下一个"——避免用户随手填到已经过去的号上
    if (viaRelay && mode == 4) {
        attackIndexSpin_->setValue(c2sDataCount_ + 1);
    } else if (viaRelay && mode == 5) {
        attackIndexSpin_->setValue(c2sPacketCount_ + 1);
    }
    updateAttackTargetHint();
}

void MainWindow::updateAttackTargetHint() {
    if (attackTargetHint_ == nullptr || attackTargetBox_ == nullptr) {
        return;
    }
    if (attackSourceBox_->currentIndex() != 0) {
        attackTargetHint_->setText("端点视角：只能打「本端最近一个已发送的包」，与目标下拉无关。");
        return;
    }
    switch (attackTargetBox_->currentData().toInt()) {
        case 3:
            attackTargetHint_->setText(
                QString("「最近一条短消息」立即生效，用的是最近一条已转发的 DATA"
                        "（至今 %1 条）；一条都还没有时会明确报错。")
                    .arg(c2sDataCount_));
            break;
        case 4:
            attackTargetHint_->setText(
                QString("「第 N 条短消息」只数 DATA，不受 4 个握手包干扰；"
                        "已转发 %1 条，下一条是第 %2 条。")
                    .arg(c2sDataCount_)
                    .arg(c2sDataCount_ + 1));
            break;
        case 5:
            attackTargetHint_->setText(
                QString("「第 N 个包」从连接建立起算（含 4 个握手包）；"
                        "已转发 %1 个，下一个是第 %2 个。")
                    .arg(c2sPacketCount_)
                    .arg(c2sPacketCount_ + 1));
            break;
        case 1:
            attackTargetHint_->setText(
                "点「发起攻击」后排队：下一条短消息经过中继时生效（发一条消息即可触发）。");
            break;
        case 2:
            attackTargetHint_->setText(
                "点「发起攻击」后排队：下一个文件块经过中继时生效。");
            break;
        default:
            attackTargetHint_->setText(
                "点「发起攻击」后排队：下一个包经过中继时生效（发一条消息即可触发）。");
            break;
    }
}

void MainWindow::highlightRejectGate(int gate) {
    for (int i = 0; i < kRejectGates; ++i) {
        if (gateChips_[i] != nullptr) {
            gateChips_[i]->setStyleSheet(chipStyle(gate == i + 1));
        }
    }
}

void MainWindow::onLaunchAttack() {
    const bool viaRelay = attackSourceBox_->currentIndex() == 0;
    const QString kind = attackKindBox_->currentText();
    const int targetMode = attackTargetBox_->currentData().toInt();
    const QString target = attackTargetBox_->currentText();

    if (!viaRelay) {
        // 端点视角：复用原有的"本端构造攻击包"路径（只能打最近一个已发送的包）
        lastAttackAction_ = QString("%1（端点视角 · 最近一个已发送的包）").arg(kind);
        if (kind == QStringLiteral("重放")) {
            onReplay();
        } else {
            onTamper();
        }
        appendAttackHistory("端点视角", kind, "最近一个已发送的包", "—", "已发出，等待对端判定");
        return;
    }

    if (!mitm_->isRunning()) {
        attackResultLabel_->setText(
            "中间人没有在运行。请先到「中间人链路」页签点「启动中继」，\n"
            "并把本端的对端地址/端口指向中继的监听端口（例如 127.0.0.1:9400）。");
        attackResultLabel_->setStyleSheet("color:#D29922;");
        return;
    }
    if (targetMode == 3 && (kind == QStringLiteral("丢弃") || kind == QStringLiteral("延迟"))) {
        attackResultLabel_->setText(
            "「最近一条短消息」只能配合篡改 / 重放：那个包早就转发过去了，\n"
            "丢弃和延迟只能作用于「下一个」还没转发的包。");
        attackResultLabel_->setStyleSheet("color:#D29922;");
        return;
    }
    // 序号必须指向"将来"的包：填了已经过去的号，攻击永远不会触发 ——
    // 这正是"点了没反应、会话照常"的成因，所以这里当场拦下来并说清怎么改。
    if (targetMode == 4 && attackIndexSpin_->value() <= c2sDataCount_) {
        attackResultLabel_->setText(
            QString("第 %1 条短消息已经过去了（至今已转发 %2 条），这个攻击永远不会触发。\n"
                    "请改用「下一条短消息」或「最近一条短消息」，或把序号改成 %3。")
                .arg(attackIndexSpin_->value())
                .arg(c2sDataCount_)
                .arg(c2sDataCount_ + 1));
        attackResultLabel_->setStyleSheet("color:#D29922;");
        return;
    }
    if (targetMode == 5 && attackIndexSpin_->value() <= c2sPacketCount_) {
        attackResultLabel_->setText(
            QString("第 %1 个包已经过去了（至今已转发 %2 个，含 4 个握手包），"
                    "这个攻击永远不会触发。\n"
                    "请改用「下一个包」，或把序号改成 %3。")
                .arg(attackIndexSpin_->value())
                .arg(c2sPacketCount_)
                .arg(c2sPacketCount_ + 1));
        attackResultLabel_->setStyleSheet("color:#D29922;");
        return;
    }

    QString command;
    if (kind == QStringLiteral("重放")) {
        command = QStringLiteral("replay");
    } else if (kind == QStringLiteral("丢弃")) {
        command = QStringLiteral("drop");
    } else if (kind == QStringLiteral("延迟")) {
        command = QStringLiteral("delay 800");
    } else {
        command = QStringLiteral("tamper");
    }
    switch (targetMode) {
        case 1: command += QStringLiteral(" --type DATA"); break;
        case 2: command += QStringLiteral(" --type FILE_CHUNK"); break;
        case 3: command += QStringLiteral(" --last --type DATA"); break;
        case 4:
            command += QStringLiteral(" --type DATA --index %1").arg(attackIndexSpin_->value());
            break;
        case 5: command += QStringLiteral(" --index %1").arg(attackIndexSpin_->value()); break;
        default: break;  // 0 = 下一个包
    }
    command += QStringLiteral(" --dir c2s");
    mitm_->sendCommand(command);

    const QString targetShown = (targetMode == 4 || targetMode == 5)
                                    ? QString("%1（第 %2）").arg(target).arg(attackIndexSpin_->value())
                                    : target;
    lastAttackAction_ = QString("%1（中间人 · 目标：%2）").arg(kind, targetShown);
    const QString waiting =
        targetMode == 3
            ? QStringLiteral("已注入（最近一条包，立即生效）")
            : QStringLiteral("已排队：等目标包经过中继时生效 —— 现在发一条消息就会触发");
    attackResultLabel_->setText(
        QString("动作：%1\n拦截关卡：%2\n结果：—").arg(lastAttackAction_, waiting));
    attackResultLabel_->setStyleSheet("color:#D29922;");
    highlightRejectGate(0);
    appendLog(QString("【攻击演示】中间人下发命令：%1").arg(command));
}

void MainWindow::onReconnectClicked() {
    if (attackSourceBox_->currentIndex() == 0) {
        // 中继一次只服务一条连接：重连前必须换一个新进程（旧的可能还在收尾）
        mitm_->stopRelay();
        if (!startRelayFromUi()) {
            return;
        }
        appendLog("已重启 Eve 中继，等它开始监听后再连接…");
        pendingReconnectAfterRelay_ = true;
        QTimer::singleShot(4000, this, [this]() {
            if (pendingReconnectAfterRelay_) {
                pendingReconnectAfterRelay_ = false;
                appendLog("[WARN] 等中继监听超时，仍然尝试连接");
                onStartClicked();
            }
        });
        return;
    }
    appendLog("重新建立会话…");
    onStartClicked();
}

bool MainWindow::startRelayFromUi() {
    if (mitm_->isRunning()) {
        return true;
    }
    QString error;
    // 中继原始日志与审计日志同目录（和 attack_log.txt 一个思路：证据集中放）
    QString logDir = QFileInfo(accessLogEdit_->text().trimmed()).absolutePath();
    if (logDir.isEmpty()) {
        logDir = QDir::currentPath();
    }
    const QString relayLog = QDir(logDir).filePath(QStringLiteral("relay_log.txt"));
    if (!mitm_->startRelay(static_cast<quint16>(relayListenSpin_->value()),
                           QStringLiteral("127.0.0.1"),
                           static_cast<quint16>(relayTargetSpin_->value()), QString(), &error,
                           relayLog)) {
        QMessageBox::warning(this, "启动中继失败", error);
        return false;
    }
    relayLogEdit_->appendPlainText(QString("[UI] 启动 Eve 中继：127.0.0.1:%1 → 127.0.0.1:%2")
                                       .arg(relayListenSpin_->value())
                                       .arg(relayTargetSpin_->value()));
    appendLog(QString("【中间人】已启动 Eve 中继（监听 %1 → 目标 127.0.0.1:%2）")
                  .arg(relayListenSpin_->value())
                  .arg(relayTargetSpin_->value()));
    return true;
}

void MainWindow::onRelayStart() {
    startRelayFromUi();
}

void MainWindow::onRelayStop() {
    mitm_->stopRelay();
    appendLog("【中间人】已停止 Eve 中继");
}

void MainWindow::onRelayLog(const QString& line) {
    relayLogEdit_->appendPlainText(line);
    // 中继的 ERR 要直接显示在攻击面板上：用户最容易忽略"日志里其实说了原因"
    if (line.startsWith(QStringLiteral("ERR "))) {
        attackResultLabel_->setText("这次攻击没有生效：\n" + line.mid(4));
        attackResultLabel_->setStyleSheet("color:#D29922;");
        appendLog("【攻击演示】" + line);
        return;
    }
    if (line.startsWith(QStringLiteral("ATTACK ")) || line.startsWith(QStringLiteral("CLOSED ")) ||
        line.startsWith(QStringLiteral("FATAL "))) {
        appendLog("【中间人】" + line);
    }
}

void MainWindow::onRelayPacket(const MitmPacketInfo& packet) {
    // 界面自己数一遍：序号到底怎么数、现在轮到第几个，用户要能看见
    if (packet.direction == QStringLiteral("C2S")) {
        const int index = packet.index.toInt();
        if (index > c2sPacketCount_) {
            c2sPacketCount_ = index;
        }
        if (packet.type == QStringLiteral("DATA")) {
            ++c2sDataCount_;
        }
    } else {
        const int index = packet.index.toInt();
        if (index > s2cPacketCount_) {
            s2cPacketCount_ = index;
        }
    }
    if (relayProgressLabel_ != nullptr) {
        relayProgressLabel_->setText(
            QString("链路已转发：C2S %1 个（其中短消息 %2 条）｜ S2C %3 个"
                    "　→ 下一个 C2S 是第 %4 个")
                .arg(c2sPacketCount_)
                .arg(c2sDataCount_)
                .arg(s2cPacketCount_)
                .arg(c2sPacketCount_ + 1));
    }
    updateAttackTargetHint();
    if (packet.undecodable) {
        packetInspectEdit_->appendPlainText(
            QString("#%1 %2 无法解析（%3 字节）").arg(packet.index, packet.direction, packet.length));
        return;
    }
    packetInspectEdit_->appendPlainText(
        QString("#%1 %2 %3  seq=%4  len=%5\n    SessionId %6 ｜ Nonce %7\n    密文 %8… ｜ CMAC %9…")
            .arg(packet.index, packet.direction, packet.type, packet.sequence, packet.length,
                 packet.sessionId, packet.nonce, packet.cipher, packet.mac));
}

void MainWindow::onRelayAttack(const QString& kind, const QString& direction, const QString& index,
                               const QString& result) {
    const QString detail = QString("%1 · %2").arg(direction, index);
    // "ok" 容易被读成"攻击成功"：这里如实写成"已注入，判定未知"
    const QString outcome = result.startsWith(QStringLiteral("injected"))
                                ? QStringLiteral("已注入（判定未知）")
                                : result;
    appendAttackHistory("中间人", kind, detail, "—", outcome);
    appendLog(QString("【攻击演示】中继执行 %1（%2）：%3").arg(kind, detail, result));
}

void MainWindow::onRelayStats(quint64 forwarded, quint64 tampered, quint64 dropped,
                              quint64 delayed, quint64 replayed) {
    relayCounterLabel_->setText(QString("转发 %1 ｜ 篡改 %2 ｜ 丢弃 %3 ｜ 延迟 %4 ｜ 重放 %5")
                                    .arg(forwarded)
                                    .arg(tampered)
                                    .arg(dropped)
                                    .arg(delayed)
                                    .arg(replayed));
}

void MainWindow::onRelayState(const QString& state, const QString& detail) {
    relayStateLabel_->setText(QString("中继状态：%1").arg(state));
    if (detail.isEmpty()) {
        return;
    }
    relayLogEdit_->appendPlainText("[状态] " + detail);
    // 剧本：等中继真正进入 LISTEN 之后再让本端去连（否则会 connection refused）
    if (pendingReconnectAfterRelay_ && state == QStringLiteral("监听中")) {
        pendingReconnectAfterRelay_ = false;
        appendLog("中继已开始监听，重新建立会话");
        onStartClicked();
        return;
    }
    if (scenarioWaitingForRelay_ && state == QStringLiteral("监听中")) {
        scenarioWaitingForRelay_ = false;
        scenarioStep_ = 2;
        QTimer::singleShot(300, this, &MainWindow::runScenarioStep);
        return;
    }
    if (scenarioWaitingForRelay_ && state == QStringLiteral("启动失败")) {
        scenarioWaitingForRelay_ = false;
        scenarioStep_ = 0;
        appendLog("[ERROR] 剧本中止：中继启动失败——" + detail);
    }
}

void MainWindow::appendAttackHistory(const QString& source, const QString& kind,
                                     const QString& detail, const QString& gate,
                                     const QString& result) {
    if (attackHistory_ == nullptr) {
        return;
    }
    const int row = attackHistory_->rowCount();
    attackHistory_->insertRow(row);
    const QStringList cells = {stamp(), source,
                               detail.isEmpty() ? kind : QString("%1（%2）").arg(kind, detail),
                               gate, result};
    for (int column = 0; column < cells.size(); ++column) {
        attackHistory_->setItem(row, column, new QTableWidgetItem(cells.at(column)));
    }
    attackHistory_->scrollToBottom();
}

void MainWindow::onExportHistory() {
    if (attackHistory_ == nullptr || attackHistory_->rowCount() == 0) {
        appendLog("[WARN] 攻击历史是空的，没有可导出的内容");
        return;
    }
    const QString directory = resolvePath("experiment_data", "..");
    const QString suggested = QDir(directory).filePath(
        QString("attack_history_%1.csv").arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")));
    const QString path =
        QFileDialog::getSaveFileName(this, "导出攻击历史", suggested, "CSV (*.csv)");
    if (path.isEmpty()) {
        return;
    }
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        appendLog("[ERROR] 无法写入攻击历史：" + path);
        return;
    }
    QTextStream stream(&file);
    stream.setCodec("UTF-8");
    stream << "\xEF\xBB\xBF";  // BOM：Excel 打开 CSV 不乱码
    const QStringList headers = {"时间", "来源", "方式", "拦截关卡", "结果"};
    stream << headers.join(',') << '\n';
    for (int row = 0; row < attackHistory_->rowCount(); ++row) {
        QStringList cells;
        for (int column = 0; column < attackHistory_->columnCount(); ++column) {
            const QTableWidgetItem* item = attackHistory_->item(row, column);
            QString text = item != nullptr ? item->text() : QString();
            text.replace('"', "\"\"");
            cells << QString("\"%1\"").arg(text);
        }
        stream << cells.join(',') << '\n';
    }
    file.close();
    appendLog("已导出攻击历史：" + path);
}

void MainWindow::onScenarioClicked() {
    if (scenarioStep_ != 0) {
        appendLog("剧本已经在运行了");
        return;
    }
    scenarioStep_ = 1;
    attackSourceBox_->setCurrentIndex(0);  // 剧本一律走"中间人"
    eveTabs_->setCurrentIndex(0);
    appendLog("===== 一键攻击剧本开始：篡改 → 重放 → 丢弃（全部经 Eve 中继执行）=====");
    runScenarioStep();
}

void MainWindow::runScenarioStep() {
    switch (scenarioStep_) {
        case 1: {  // 起中继
            if (!startRelayFromUi()) {
                scenarioStep_ = 0;
                return;
            }
            scenarioAttackKind_ = QStringLiteral("篡改");
            // 等中继真正 LISTEN（onRelayState 里接力），并留一个兜底超时
            scenarioWaitingForRelay_ = true;
            QTimer::singleShot(5000, this, [this]() {
                if (scenarioWaitingForRelay_) {
                    scenarioWaitingForRelay_ = false;
                    scenarioStep_ = 2;
                    appendLog("剧本：等中继监听超时，仍然尝试连接");
                    runScenarioStep();
                }
            });
            return;
        }
        case 2: {  // 本端连到中继（剧本需要本端当客户端）
            roleBox_->setCurrentIndex(0);
            hostEdit_->setText(QStringLiteral("127.0.0.1"));
            portSpin_->setValue(relayListenSpin_->value());
            appendLog(QString("剧本：本端改为客户端并连接中继端口 %1").arg(relayListenSpin_->value()));
            onStartClicked();
            // 等会话建立（onEstablished 里接力），并留一个兜底超时
            scenarioWaitingForSession_ = true;
            QTimer::singleShot(6000, this, [this]() {
                if (scenarioWaitingForSession_) {
                    scenarioWaitingForSession_ = false;
                    scenarioStep_ = 4;
                    appendLog("剧本：等会话建立超时，跳到下一轮");
                    runScenarioStep();
                }
            });
            return;
        }
        case 3: {  // 下发攻击 + 发一条探针消息（它才是被攻击的那个包）
            QString command;
            if (scenarioAttackKind_ == QStringLiteral("篡改")) {
                command = QStringLiteral("tamper --dir c2s");
            } else if (scenarioAttackKind_ == QStringLiteral("重放")) {
                command = QStringLiteral("replay --dir c2s");
            } else {
                command = QStringLiteral("drop --dir c2s");
            }
            mitm_->sendCommand(command);
            lastAttackAction_ = QString("%1（中间人 · 剧本）").arg(scenarioAttackKind_);
            worker_->requestSendText(QString("剧本探针：%1").arg(scenarioAttackKind_));
            appendLog(QString("剧本：已下发 %1，并发出探针消息").arg(scenarioAttackKind_));
            scenarioStep_ = 4;
            QTimer::singleShot(4500, this, &MainWindow::runScenarioStep);
            return;
        }
        case 4: {  // 收尾：进入下一轮或结束
            if (scenarioAttackKind_ == QStringLiteral("篡改")) {
                scenarioAttackKind_ = QStringLiteral("重放");
            } else if (scenarioAttackKind_ == QStringLiteral("重放")) {
                scenarioAttackKind_ = QStringLiteral("丢弃");
            } else {
                scenarioStep_ = 0;
                appendLog("===== 一键攻击剧本结束：结果见「攻击历史」页签（可导出 CSV）=====");
                attackResultLabel_->setText(
                    "剧本已完成（篡改 → 重放 → 丢弃）。\n"
                    "前两项会被内核在 ⑥ / ⑦ 关拦下；「丢弃」属于可用性攻击，密码学防不住，"
                    "只表现为超时——这一点如实写在报告的 limitation 里。");
                attackResultLabel_->setStyleSheet("color:#59646E;");
                return;
            }
            scenarioStep_ = 5;
            QTimer::singleShot(500, this, &MainWindow::runScenarioStep);
            return;
        }
        case 5: {  // 重新起中继（它在上一轮结束后已退出）
            mitm_->stopRelay();  // 先确保上一轮的中继收摊，端口释放
            if (!startRelayFromUi()) {
                scenarioStep_ = 0;
                return;
            }
            scenarioWaitingForRelay_ = true;
            QTimer::singleShot(5000, this, [this]() {
                if (scenarioWaitingForRelay_) {
                    scenarioWaitingForRelay_ = false;
                    scenarioStep_ = 2;
                    appendLog("剧本：等中继监听超时，仍然尝试连接");
                    runScenarioStep();
                }
            });
            return;
        }
        default:
            scenarioStep_ = 0;
            return;
    }
}
