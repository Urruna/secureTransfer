// ============================================================================
//  SecureTransfer - 图形界面：主题（浅色扁平）
//  file: apps/ui/app_theme.h
//
//  视觉取值全部来自 docs/SecureTransfer_UI改造草图.html（变量 → 具体色值）：
//    background-primary  #FFFFFF   页面 / 卡片
//    background-secondary#F5F6F8   页面底色、次级块
//    border-tertiary     #E3E5E8   描边
//    text-primary        #1F2328   正文
//    text-secondary      #59636E   次要文字
//    text-tertiary       #8B949E   占位符
//    success             #12A150   已建立 / 成功 / 进度
//    danger              #D1242F   拒绝 / 错误
//    info                #1F6FEB   主按钮 / 本端气泡
//    warning             #D29922   握手中 / 提示
//
//  为什么把 QSS 内嵌成字符串（而不是 .qrc + .qss 资源）：
//    1. 不引入 AUTORCC / Qt5::Svg 的额外构建与打包依赖（计划 R2）；
//    2. 打包后的 exe 不依赖"样式文件放在哪"，任何工作目录都能正确上样式。
//  图标同理：一律用 QStyle::standardIcon()，不附带任何图片资源。
//
//  ⚠ 使用时机（计划 R1）：QSS 会改变控件的 sizeHint，而主窗口的防回归机制是
//     "每个控件最小高度 = sizeHint()"。所以必须在**创建任何控件之前**调用
//     stui::applyTheme(app)，否则最小高度会按旧尺寸计算，小窗口下文字会被压掉。
// ============================================================================

#ifndef SECURETRANSFER_APPS_UI_APP_THEME_H
#define SECURETRANSFER_APPS_UI_APP_THEME_H

#include <QApplication>
#include <QColor>
#include <QString>

namespace stui {

// ---- 语义色（供代码里需要按状态取色的地方使用，避免硬编码散落） ----
inline QColor colorPrimary() { return QColor("#1F6FEB"); }
inline QColor colorSuccess() { return QColor("#12A150"); }
inline QColor colorWarning() { return QColor("#D29922"); }
inline QColor colorDanger() { return QColor("#D1242F"); }
inline QColor colorSecondaryText() { return QColor("#59636E"); }

// ---- 日志级别（与样式表里的颜色一一对应） ----
enum class LogLevel { kInfo = 0, kSuccess = 1, kWarn = 2, kError = 3 };

inline QColor colorForLevel(LogLevel level) {
    switch (level) {
        case LogLevel::kSuccess: return colorSuccess();
        case LogLevel::kWarn:    return colorWarning();
        case LogLevel::kError:   return colorDanger();
        case LogLevel::kInfo:    break;
    }
    return QColor("#1F2328");
}

/// 样式表：浅色扁平，取值见文件头注释。
inline const char* styleSheet() {
    return R"QSS(
QWidget {
    font-family: "Microsoft YaHei UI", "Noto Sans CJK SC", "PingFang SC", sans-serif;
    font-size: 9pt;
    color: #1F2328;
}
QMainWindow, QWidget#centralArea, QScrollArea#cardScroll { background: #F5F6F8; }

/* ---- 顶部标题条 / 工具条 / 状态栏 ---- */
QFrame#headerBar { background: #F5F6F8; border-bottom: 1px solid #E3E5E8; }
QLabel#appTitle { font-size: 13pt; font-weight: 600; }
QLabel#statusText { font-size: 9pt; color: #59636E; }
QFrame#toolBar { background: #FFFFFF; border-bottom: 1px solid #E3E5E8; }
QStatusBar { background: #FFFFFF; border-top: 1px solid #E3E5E8; color: #59636E; }
QStatusBar::item { border: none; }

/* ---- 卡片 ---- */
QGroupBox {
    background: #FFFFFF;
    border: 1px solid #E3E5E8;
    border-radius: 8px;
    margin-top: 12px;
    padding: 10px 10px 10px 10px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #59636E;
    font-weight: 500;
}
QFrame#tile { background: #F5F6F8; border-radius: 6px; }
QLabel#tileValue { font-size: 14pt; font-weight: 600; }
QLabel#tileCaption { font-size: 8pt; color: #59636E; }

/* ---- 按钮 ---- */
QPushButton {
    background: #FFFFFF;
    border: 1px solid #E3E5E8;
    border-radius: 6px;
    padding: 5px 12px;
}
QPushButton:hover { background: #F5F6F8; }
QPushButton:pressed { background: #EDEFF2; }
QPushButton:disabled { color: #8B949E; border-color: #EDEFF2; }
QPushButton#primary {
    background: #1F6FEB; color: #FFFFFF; border: none; font-weight: 500;
}
QPushButton#primary:hover { background: #1A5FCC; }
QPushButton#primary:disabled { background: #A9C7F5; color: #FFFFFF; }
QPushButton#danger { color: #D1242F; border: 1px solid #F1B5B9; background: #FFFFFF; }
QPushButton#danger:hover { background: #FDECEE; }
QPushButton#danger:disabled { color: #C9A0A3; border-color: #F3DADC; }

/* ---- 输入控件 ---- */
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextEdit {
    background: #FFFFFF;
    border: 1px solid #E3E5E8;
    border-radius: 6px;
    padding: 4px 6px;
    selection-background-color: #1F6FEB;
    selection-color: #FFFFFF;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {
    border-color: #1F6FEB;
}
QLineEdit:read-only { background: #F5F6F8; color: #59636E; }
QPlainTextEdit#logView, QTextEdit#historyView { border: 1px solid #E3E5E8; }
QComboBox::drop-down { border: none; width: 18px; }
QComboBox QAbstractItemView {
    background: #FFFFFF;
    border: 1px solid #E3E5E8;
    selection-background-color: #E7F0FF;
    selection-color: #1F2328;
}
QSpinBox::up-button, QSpinBox::down-button { width: 16px; }

/* ---- 进度条 ---- */
QProgressBar {
    background: #F5F6F8; border: 1px solid #E3E5E8; border-radius: 5px;
    height: 10px; text-align: center; color: #59636E;
}
QProgressBar::chunk { background: #12A150; border-radius: 4px; }

/* ---- 分栏 ---- */
QSplitter::handle { background: #E3E5E8; }
QSplitter::handle:horizontal { width: 4px; }
QScrollArea { border: none; }
)QSS";
}

/// 应用主题：必须在创建任何控件之前调用（见文件头 R1 说明）。
inline void applyTheme(QApplication& app) {
    app.setStyleSheet(QString::fromUtf8(styleSheet()));
}

}  // namespace stui

#endif  // SECURETRANSFER_APPS_UI_APP_THEME_H
