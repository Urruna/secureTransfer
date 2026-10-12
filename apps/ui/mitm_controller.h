// ============================================================================
//  SecureTransfer - 图形界面：中间人中继控制器
//  file: apps/ui/mitm_controller.h
//
//  界面里的"链路中间人"是一个**独立进程**（`eve.exe`，见 apps/eve/），
//  本类只负责把它拉起来、给它下发攻击命令、并把它 stdout 的每一行解析成
//  Qt 信号交给界面显示。
//
//  为什么必须是独立进程：
//    "中间人"要能证明"攻击者是链路上的第三方"。如果让界面自己在进程内转发，
//    就退化成"端点自己改自己的发送路径"，证据力完全不同。
//
//  与中继的接口（stdout 行前缀固定，见 apps/eve/main.cpp）：
//      [EVE] LISTEN  port=9400 target=127.0.0.1:9000
//      [EVE] CONNECTED client=… upstream=…
//      [EVE] PACKET  dir=C2S n=5 type=DATA seq=1 sid=… nonce=… len=85 ct=… mac=…
//      [EVE] ATTACK  kind=tamper dir=C2S n=5 result=ok
//      [EVE] QUEUED  kind=drop dir=C2S n=next
//      [EVE] STATUS  forwarded=20 tampered=1 …
//      [EVE] CLOSED  dir=C2S reason=peer_closed
//  stdin 命令：tamper / drop / delay <ms> / replay / status / quit（可带 [n] [dir]）
// ============================================================================

#ifndef SECURETRANSFER_APPS_UI_MITM_CONTROLLER_H
#define SECURETRANSFER_APPS_UI_MITM_CONTROLLER_H

#include <QObject>
#include <QString>

class QProcess;
class QTimer;

/// 一个包的结构化信息（从 `[EVE] PACKET …` 行解析而来）。
struct MitmPacketInfo {
    QString direction;   ///< C2S / S2C
    QString index;       ///< 该方向第几个包
    QString type;        ///< HELLO / DATA / FILE_CHUNK …
    QString sequence;
    QString sessionId;
    QString nonce;
    QString length;
    QString cipher;      ///< 密文前 8 字节（Eve 能看到的"密文"）
    QString mac;
    bool undecodable = false;

    /// 供"数据包检查器"直接显示的一行摘要。
    QString summary() const;
};

class MitmController : public QObject {
    Q_OBJECT

public:
    explicit MitmController(QObject* parent = nullptr);
    ~MitmController() override;

    /// 启动中继进程（不阻塞）。evePath 为空时用"与界面同一个目录下的 eve.exe"。
    /// logPath 非空时，中继的每一行原始输出都会追加到该文件（作为演示证据留档）。
    /// @return false 时 error 给出原因（找不到 eve.exe / 端口占用由中继自己报）
    bool startRelay(quint16 listenPort, const QString& targetHost, quint16 targetPort,
                    const QString& evePath, QString* error, const QString& logPath = QString());

    /// 让中继退出（发 quit，并在超时后强杀）。
    void stopRelay();

    bool isRunning() const;

    /// 下发一条中继命令（tamper / drop / delay 800 / replay / status / quit）。
    void sendCommand(const QString& command);

    /// 默认的 eve.exe 路径：与 st_ui.exe 同目录。
    static QString defaultEvePath();

signals:
    /// 中继的原始输出行（已去掉 `[EVE] ` 前缀）。
    void relayLine(const QString& line);
    /// 解析出的数据包（Eve 视角）。
    void relayPacket(const MitmPacketInfo& packet);
    /// 一次攻击的执行结果：kind / direction / index / result。
    void relayAttack(const QString& kind, const QString& direction, const QString& index,
                     const QString& result);
    /// 统计（来自 STATUS 行或进程退出后的收尾输出）。
    void relayStats(quint64 forwarded, quint64 tampered, quint64 dropped, quint64 delayed,
                    quint64 replayed);
    /// 中继进程状态：未启动 / 监听中 / 已连接 / 已结束 / 启动失败。
    void relayState(const QString& state, const QString& detail);

private slots:
    void onReadyRead();
    void onProcessFinished(int exitCode);

private:
    void handleLine(const QString& line);

    QProcess* process_ = nullptr;
    QString buffer_;
    QString logPath_;
};

#endif  // SECURETRANSFER_APPS_UI_MITM_CONTROLLER_H
