// ============================================================================
//  SecureTransfer - 第三部分：Qt 图形界面入口
//  file: apps/ui/main.cpp
//
//  运行方式（在虚拟机桌面里）：
//        cd /home/securityTransfer/build
//        ./st_ui
//
//  说明：界面只做"人机交互"，所有安全功能（AES-CTR 加密、CMAC 完整性、
//        身份认证、密钥分发、防重放、访问控制、文件分块传输）都还是
//        第一部分 / 第二部分 / 第三部分已经实现并测试过的 C++ 模块，
//        界面不重复实现任何密码学逻辑。
// ============================================================================

#include <QApplication>
#include <QFont>
#include <QStyle>
#include <QStringList>

#include "app_theme.h"
#include "main_window.h"

#include "common/console.h"

namespace {

/// 打印用法（中文说明，便于演示时直接照着敲）。
void printUsage() {
    printf(R"(用法：./st_ui [选项]

  --server / --client        角色：服务端（Bob，默认等待连接）/ 客户端（Alice）
  --host <地址>              对端地址（客户端用，默认 127.0.0.1）
  --port <端口>              端口（默认 9000）
  --id <身份>                本端身份（alice / eve / mallory / bob）
  --peer <身份>              对端身份（握手时校验；不分角色都可用）
  --key <文件>               密钥配置（默认 configs/keys.conf）
  --policy <文件>            访问控制策略（默认 configs/access_policy.conf）
  --out-dir <目录>           接收文件目录（默认 experiment_data/received）
  --access-log <文件>        审计日志（默认 experiment_data/access_log.txt）
  --auto                     打开界面后立即开始会话（用于演示/自动截图）
  --send-text <内容>         会话建立后自动发送该短消息（可重复）
  --send-file <路径>         会话建立后自动发送该文件（可重复）
  --send-image <路径>        会话建立后自动发送该图像（可重复）
  --cmd <WHOAMI|VIEW_LOG>    会话建立后自动发送该命令（可重复）
  --geometry <宽x高>         强制窗口尺寸，例如 --geometry 940x600（复现小窗口布局问题）
  --print-geometry           打印各控件实际尺寸后退出（排查"文字显示不全"用）
  --relay                    启动界面时就把 Eve 中继拉起来（真实链路中间人）
  --relay-listen <端口>      中继监听端口（默认 9400）；本端"端口"要指向它
  --relay-target <端口>      中继转发到的真实服务端端口（默认 9000）
  --scenario                 自动运行"一键攻击剧本"（篡改 → 重放 → 丢弃，全部经中继）
  --help                     显示本帮助

不带任何参数时，就是一个可以直接点击操作的图形界面。
)");
}

}  // namespace

int main(int argc, char** argv) {
    stconsole::ensureUtf8();

    // 高 DPI：Qt 5 必须在 QApplication 构造**之前**设置，否则高 DPI 屏上文字发虚。
    // （本机是 150% 缩放的 2160×1440 屏，开启后控件按逻辑像素布局，
    //   主窗口的最小尺寸/最小高度机制仍然有效。）
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    QApplication app(argc, argv);
    QApplication::setApplicationName("SecureTransfer");
    QApplication::setApplicationDisplayName("SecureTransfer — 安全的信息传输套件");

    // 主题必须在创建任何控件之前应用（QSS 会影响 sizeHint，见 app_theme.h 的说明）
    stui::applyTheme(app);
    if (app.style() != nullptr) {
        // 用系统标准图标当窗口图标，避免附带图片资源
        app.setWindowIcon(app.style()->standardIcon(QStyle::SP_ComputerIcon));
    }

    // 统一设置稍大一点的字体，保证中文显示清晰
    QFont font = app.font();
    font.setPointSize(10);
    app.setFont(font);

    MainWindow::Options options;
    const QStringList args = app.arguments();
    for (int i = 1; i < args.size(); ++i) {
        const QString arg = args.at(i);
        const bool hasNext = (i + 1) < args.size();
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else if (arg == "--server") {
            options.isServer = true;
            options.roleSpecified = true;
        } else if (arg == "--client") {
            options.isServer = false;
            options.roleSpecified = true;
        } else if (arg == "--auto") {
            options.autoStart = true;
        } else if (arg == "--host" && hasNext) {
            options.host = args.at(++i);
        } else if (arg == "--port" && hasNext) {
            options.port = args.at(++i).toInt();
        } else if (arg == "--id" && hasNext) {
            options.localId = args.at(++i);
        } else if (arg == "--peer" && hasNext) {
            options.peerId = args.at(++i);
        } else if (arg == "--key" && hasNext) {
            options.keyFile = args.at(++i);
        } else if (arg == "--policy" && hasNext) {
            options.policyFile = args.at(++i);
        } else if (arg == "--out-dir" && hasNext) {
            options.outDir = args.at(++i);
        } else if (arg == "--access-log" && hasNext) {
            options.accessLog = args.at(++i);
        } else if (arg == "--send-text" && hasNext) {
            options.actions.append(qMakePair(QString("text"), args.at(++i)));
        } else if (arg == "--send-file" && hasNext) {
            options.actions.append(qMakePair(QString("file"), args.at(++i)));
        } else if (arg == "--send-image" && hasNext) {
            options.actions.append(qMakePair(QString("image"), args.at(++i)));
        } else if (arg == "--cmd" && hasNext) {
            options.actions.append(qMakePair(QString("cmd"), args.at(++i)));
        } else if (arg == "--geometry" && hasNext) {
            options.geometry = args.at(++i);
        } else if (arg == "--print-geometry") {
            options.printGeometry = true;
        } else if (arg == "--relay") {
            options.startRelay = true;
        } else if (arg == "--relay-listen" && hasNext) {
            options.relayListen = args.at(++i).toInt();
        } else if (arg == "--relay-target" && hasNext) {
            options.relayTarget = args.at(++i).toInt();
        } else if (arg == "--scenario") {
            options.scenario = true;
        }
    }

    MainWindow window;
    window.applyOptions(options);
    window.show();
    return app.exec();
}
