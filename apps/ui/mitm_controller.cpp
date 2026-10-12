// ============================================================================
//  SecureTransfer - 图形界面：中间人中继控制器（实现）
//  file: apps/ui/mitm_controller.cpp
// ============================================================================

#include "mitm_controller.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QStringList>

namespace {

/// 从 `key=value` 形式的一行里取出某个字段（取不到返回空串）。
QString fieldOf(const QString& line, const QString& key) {
    const QString needle = key + "=";
    const int start = line.indexOf(needle);
    if (start < 0) {
        return QString();
    }
    const int begin = start + needle.size();
    int end = line.indexOf(QLatin1Char(' '), begin);
    if (end < 0) {
        end = line.size();
    }
    return line.mid(begin, end - begin);
}

/// `key=value` 里的 value（用于 result=… 这种可能带括号与中文的字段）。
QString tailOf(const QString& line, const QString& key) {
    const QString needle = key + "=";
    const int start = line.indexOf(needle);
    if (start < 0) {
        return QString();
    }
    return line.mid(start + needle.size()).trimmed();
}

}  // namespace

QString MitmPacketInfo::summary() const {
    if (undecodable) {
        return QString("#%1 %2 无法解析（长度 %3）").arg(index, direction, length);
    }
    return QString("#%1 %2 %3  seq=%4  len=%5\nSessionId %6\nNonce %7\n密文(前8字节) %8\nCMAC %9")
        .arg(index, direction, type, sequence, length, sessionId, nonce, cipher, mac);
}

MitmController::MitmController(QObject* parent) : QObject(parent) {}

MitmController::~MitmController() {
    if (process_ != nullptr) {
        process_->kill();
        process_->waitForFinished(1000);
    }
}

QString MitmController::defaultEvePath() {
#ifdef _WIN32
    const QString name = QStringLiteral("eve.exe");
#else
    const QString name = QStringLiteral("eve");
#endif
    return QDir(QCoreApplication::applicationDirPath()).filePath(name);
}

bool MitmController::startRelay(quint16 listenPort, const QString& targetHost, quint16 targetPort,
                                const QString& evePath, QString* error, const QString& logPath) {
    if (isRunning()) {
        if (error != nullptr) {
            *error = QStringLiteral("中继已经在运行");
        }
        return false;
    }
    const QString path = evePath.isEmpty() ? defaultEvePath() : evePath;
    if (!QFileInfo::exists(path)) {
        if (error != nullptr) {
            *error = QStringLiteral("找不到中继程序：%1\n（请先编译 eve 目标，或与 st_ui 放在同一目录）")
                         .arg(path);
        }
        return false;
    }

    process_ = new QProcess(this);
    process_->setProcessChannelMode(QProcess::MergedChannels);
    connect(process_, &QProcess::readyReadStandardOutput, this, &MitmController::onReadyRead);
    connect(process_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this](int exitCode, QProcess::ExitStatus) { onProcessFinished(exitCode); });

    buffer_.clear();
    const QString target = QString("%1:%2").arg(targetHost).arg(targetPort);
    logPath_ = logPath;
    if (!logPath_.isEmpty()) {
        const QFileInfo info(logPath_);
        if (!info.absoluteDir().exists()) {
            QDir().mkpath(info.absolutePath());
        }
        QFile file(logPath_);
        if (file.open(QIODevice::Append | QIODevice::Text)) {
            file.write(QString("\n===== 中继启动 %1：127.0.0.1:%2 → %3 =====\n")
                           .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"))
                           .arg(listenPort)
                           .arg(target)
                           .toUtf8());
            file.close();
        }
    }
    process_->start(path, {QStringLiteral("--listen"), QString::number(listenPort),
                           QStringLiteral("--target"), target});
    if (!process_->waitForStarted(5000)) {
        if (error != nullptr) {
            *error = QStringLiteral("无法启动中继进程：%1").arg(path);
        }
        process_->deleteLater();
        process_ = nullptr;
        return false;
    }
    // 注意：这里只是"进程起来了"，还不能算"在监听"——真正在监听的时刻是
    // 中继打印出 `LISTEN port=…` 那一行（handleLine 里会再发一次 relayState）。
    // 界面要连中继时必须等那一次，否则会撞上 connection refused。
    emit relayState(QStringLiteral("启动中"),
                    QStringLiteral("正在启动 Eve 中继（127.0.0.1:%1 → %2）").arg(listenPort).arg(target));
    return true;
}

void MitmController::stopRelay() {
    if (process_ == nullptr) {
        return;
    }
    if (process_->state() != QProcess::NotRunning) {
        sendCommand(QStringLiteral("quit"));
        if (!process_->waitForFinished(1500)) {
            process_->kill();
            process_->waitForFinished(1000);
        }
    }
    emit relayState(QStringLiteral("未启动"), QString());
}

bool MitmController::isRunning() const {
    return process_ != nullptr && process_->state() != QProcess::NotRunning;
}

void MitmController::sendCommand(const QString& command) {
    if (!isRunning()) {
        emit relayState(QStringLiteral("未启动"), QStringLiteral("中继没有在运行，命令被忽略"));
        return;
    }
    process_->write((command + QLatin1Char('\n')).toUtf8());
    process_->waitForBytesWritten(500);
}

void MitmController::onReadyRead() {
    if (process_ == nullptr) {
        return;
    }
    buffer_ += QString::fromUtf8(process_->readAllStandardOutput());
    int newline = buffer_.indexOf(QLatin1Char('\n'));
    while (newline >= 0) {
        const QString line = buffer_.left(newline).trimmed();
        buffer_.remove(0, newline + 1);
        if (!line.isEmpty()) {
            handleLine(line);
        }
        newline = buffer_.indexOf(QLatin1Char('\n'));
    }
}

void MitmController::onProcessFinished(int exitCode) {
    emit relayState(QStringLiteral("已结束"),
                    QStringLiteral("中继进程退出（退出码 %1）").arg(exitCode));
    if (process_ != nullptr) {
        process_->deleteLater();
        process_ = nullptr;
    }
}

void MitmController::handleLine(const QString& raw) {
    // 去掉 "[EVE] " 前缀；中继自身也会用 [INFO]/[ERROR] 打网络层日志，照原样透传。
    QString line = raw;
    const QString prefix = QStringLiteral("[EVE] ");
    if (line.startsWith(prefix)) {
        line = line.mid(prefix.size());
    }
    emit relayLine(line);
    // 原始输出落盘留档（演示证据：中继到底转发了什么、拦在哪一关）
    if (!logPath_.isEmpty()) {
        QFile file(logPath_);
        if (file.open(QIODevice::Append | QIODevice::Text)) {
            file.write((line + "\n").toUtf8());
            file.close();
        }
    }

    if (line.startsWith(QStringLiteral("PACKET "))) {
        MitmPacketInfo info;
        info.direction = fieldOf(line, QStringLiteral("dir"));
        info.index = fieldOf(line, QStringLiteral("n"));
        info.type = fieldOf(line, QStringLiteral("type"));
        info.sequence = fieldOf(line, QStringLiteral("seq"));
        info.sessionId = fieldOf(line, QStringLiteral("sid"));
        info.nonce = fieldOf(line, QStringLiteral("nonce"));
        info.length = fieldOf(line, QStringLiteral("len"));
        info.cipher = fieldOf(line, QStringLiteral("ct"));
        info.mac = fieldOf(line, QStringLiteral("mac"));
        info.undecodable = info.type == QStringLiteral("UNDECODABLE");
        emit relayPacket(info);
        return;
    }
    if (line.startsWith(QStringLiteral("ATTACK "))) {
        // "打第 N 个包"时中继给的是 n=…；"打最近一条"给的是 target=last-DATA。
        QString where = fieldOf(line, QStringLiteral("n"));
        const QString targetText = fieldOf(line, QStringLiteral("target"));
        if (!targetText.isEmpty()) {
            where = where.isEmpty() ? targetText : QString("%1/%2").arg(where, targetText);
        }
        emit relayAttack(fieldOf(line, QStringLiteral("kind")),
                         fieldOf(line, QStringLiteral("dir")),
                         where,
                         tailOf(line, QStringLiteral("result")));
        return;
    }
    if (line.startsWith(QStringLiteral("STATUS "))) {
        emit relayStats(fieldOf(line, QStringLiteral("forwarded")).toULongLong(),
                        fieldOf(line, QStringLiteral("tampered")).toULongLong(),
                        fieldOf(line, QStringLiteral("dropped")).toULongLong(),
                        fieldOf(line, QStringLiteral("delayed")).toULongLong(),
                        fieldOf(line, QStringLiteral("replayed")).toULongLong());
        return;
    }
    if (line.startsWith(QStringLiteral("LISTEN "))) {
        emit relayState(QStringLiteral("监听中"), line);
        return;
    }
    if (line.startsWith(QStringLiteral("CONNECTED "))) {
        emit relayState(QStringLiteral("已连接"), line);
        return;
    }
    if (line.startsWith(QStringLiteral("CLOSED "))) {
        emit relayState(QStringLiteral("链路已断开"), line);
        return;
    }
    if (line.startsWith(QStringLiteral("FATAL "))) {
        emit relayState(QStringLiteral("启动失败"), tailOf(line, QStringLiteral("FATAL")));
        return;
    }
}
