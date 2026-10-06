// ============================================================================
//  SecureTransfer - 第三部分：应用层（文件 / 图像传输）
//  file: src/application/file_transfer.cpp
// ============================================================================

#include "application/file_transfer.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>
#include <vector>

#include "application/crc32.h"
#include "common/log.h"
#include "common/path_utils.h"
#include "protocol/packet.h"

namespace transfer {

namespace {

const char* const kLogModule = "Transfer";

std::string joinPath(const std::string& dir, const std::string& name) {
    if (dir.empty()) {
        return name;
    }
    if (dir.back() == '/') {
        return dir + name;
    }
    return dir + "/" + name;
}

}  // namespace

// ---------------------------------------------------------------------------
//  发送端
// ---------------------------------------------------------------------------

SendResult FileSender::send(SecureSession& session,
                            const std::string& path,
                            Kind kind,
                            bool forceChunked,
                            const ProgressCallback& onProgress) {
    SendResult result;
    result.kind = kind;
    result.fileName = baseName(path);

    // openInputFile()：Windows 下用宽字符路径打开，支持中文路径（见 common/path_utils.h）
    std::ifstream input = openInputFile(path);
    if (!input) {
        result.error = "无法打开待发送文件: " + path;
        return result;
    }
    const Bytes data((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
    input.close();

    result.bytes = data.size();
    result.crc32 = Crc32::compute(data);

    const auto start = std::chrono::steady_clock::now();

    // 元数据头长度（估算）：版本+kind+mode+TLV 文件名+u64+u32+u32
    const std::size_t metaSize = 3 + 2 + result.fileName.size() + 8 + 4 + 4;
    const bool canSingleShot =
        !forceChunked && kind == Kind::kImage && (data.size() + metaSize) <= Packet::kMaxBodySize;

    if (canSingleShot) {
        // ---- 单包传输（IMAGE）：元数据 + 数据放在同一个安全数据包里 ----
        Meta meta;
        meta.kind = kind;
        meta.mode = Mode::kSingleShot;
        meta.fileName = result.fileName;
        meta.totalBytes = data.size();
        meta.crc32 = result.crc32;
        meta.inlineDataLength = static_cast<std::uint32_t>(data.size());

        Bytes body = encodeMeta(meta);
        body.insert(body.end(), data.begin(), data.end());
        if (!session.sendMessage(MessageType::kImage, body)) {
            result.error = "发送图像失败: " + session.lastError();
            return result;
        }
        result.singleShot = true;
        if (onProgress) {
            onProgress(data.size(), data.size());
        }
    } else {
        // ---- 分块传输：FILE_START → FILE_CHUNK × N → FILE_END ----
        Meta meta;
        meta.kind = kind;
        meta.mode = Mode::kChunked;
        meta.fileName = result.fileName;
        meta.totalBytes = data.size();
        meta.crc32 = result.crc32;
        meta.inlineDataLength = 0;

        // 图像也用 IMAGE 作为起始包（kind = 图像），普通文件用 FILE_START
        const MessageType startType =
            kind == Kind::kImage ? MessageType::kImage : MessageType::kFileStart;
        if (!session.sendMessage(startType, encodeMeta(meta))) {
            result.error = "发送传输起始包失败: " + session.lastError();
            return result;
        }

        std::size_t offset = 0;
        while (offset < data.size()) {
            const std::size_t chunk =
                std::min<std::size_t>(kChunkSize, data.size() - offset);
            const Bytes piece(data.begin() + static_cast<std::ptrdiff_t>(offset),
                              data.begin() + static_cast<std::ptrdiff_t>(offset + chunk));
            if (!session.sendMessage(MessageType::kFileChunk, piece)) {
                result.error = "发送数据块失败: " + session.lastError();
                return result;
            }
            offset += chunk;
            ++result.chunks;
            if (onProgress) {
                onProgress(offset, data.size());
            }
        }

        if (!session.sendMessage(MessageType::kFileEnd,
                                 encodeEnd(result.bytes, result.crc32))) {
            result.error = "发送传输结束包失败: " + session.lastError();
            return result;
        }
    }

    const auto end = std::chrono::steady_clock::now();
    result.seconds = std::chrono::duration<double>(end - start).count();
    if (result.seconds > 0.0) {
        result.megabytesPerSecond =
            (static_cast<double>(result.bytes) / (1024.0 * 1024.0)) / result.seconds;
    }
    result.ok = true;
    return result;
}

// ---------------------------------------------------------------------------
//  接收端
// ---------------------------------------------------------------------------

TransferReceiver::TransferReceiver(std::string outputDir) : outputDir_(std::move(outputDir)) {}

bool TransferReceiver::handle(MessageType type, const Bytes& body, std::string* error) {
    switch (type) {
        case MessageType::kFileStart:
        case MessageType::kImage:
            return beginTransfer(type, body, error);
        case MessageType::kFileChunk:
            return appendChunk(body, error);
        case MessageType::kFileEnd:
            return finishTransfer(body, error);
        default:
            return false;  // 不属于文件传输流程
    }
}

bool TransferReceiver::beginTransfer(MessageType type, const Bytes& body, std::string* error) {
    if (inProgress_) {
        if (error != nullptr) {
            *error = "上一个传输（" + meta_.fileName + "）尚未结束，却收到新的起始包";
        }
        return true;
    }

    Meta meta;
    Bytes payload;
    if (!decodeMeta(body, meta, payload, error)) {
        return true;  // 属于传输流程，但内容非法
    }
    if (type == MessageType::kImage && meta.kind != Kind::kImage) {
        if (error != nullptr) {
            *error = "IMAGE 消息的 kind 必须为图像";
        }
        return true;
    }

    const std::string savedPath = joinPath(outputDir_, meta.fileName);
    file_ = openOutputFile(savedPath);
    if (!file_) {
        if (error != nullptr) {
            *error = "无法创建接收文件: " + savedPath;
        }
        return true;
    }

    meta_ = meta;
    receivedBytes_ = 0;
    chunks_ = 0;
    chunkCrc_.reset();
    inProgress_ = true;
    lastResult_ = ReceiveResult{};
    lastResult_.fileName = meta.fileName;
    lastResult_.savedPath = savedPath;
    lastResult_.kind = meta.kind;

    if (meta.mode == Mode::kSingleShot) {
        // 单包传输：数据已经在起始包里，直接写入并校验
        file_.write(reinterpret_cast<const char*>(payload.data()),
                    static_cast<std::streamsize>(payload.size()));
        receivedBytes_ = payload.size();
        const std::uint32_t crc = Crc32::compute(payload);

        lastResult_.bytes = receivedBytes_;
        lastResult_.crc32 = crc;
        lastResult_.singleShot = true;
        file_.close();
        inProgress_ = false;

        if (crc != meta_.crc32 || receivedBytes_ != meta_.totalBytes) {
            lastResult_.ok = false;
            lastResult_.error = "单包传输校验失败：字节数或 CRC32 与发送端不一致";
            ++failedCount_;
            if (error != nullptr) {
                *error = lastResult_.error;
            }
            return true;
        }
        lastResult_.ok = true;
        ++completedCount_;
        ST_LOG_INFO(kLogModule, std::string("已接收 ") + kindToString(meta_.kind) + " " +
                                    meta_.fileName + "（单包，共 " +
                                    std::to_string(receivedBytes_) + " 字节）");
        return true;
    }

    ST_LOG_INFO(kLogModule, std::string("开始接收 ") + kindToString(meta_.kind) + " " +
                                meta_.fileName + "（分块，共 " +
                                std::to_string(meta_.totalBytes) + " 字节）");
    return true;
}

bool TransferReceiver::appendChunk(const Bytes& body, std::string* error) {
    if (!inProgress_) {
        if (error != nullptr) {
            *error = "收到数据块，但没有正在进行的传输";
        }
        return true;
    }
    if (receivedBytes_ + body.size() > meta_.totalBytes) {
        if (error != nullptr) {
            *error = "收到的数据超过了元数据声明的总长度";
        }
        lastResult_.ok = false;
        lastResult_.error = "数据超长";
        file_.close();
        inProgress_ = false;
        ++failedCount_;
        return true;
    }
    if (!body.empty()) {
        file_.write(reinterpret_cast<const char*>(body.data()),
                    static_cast<std::streamsize>(body.size()));
    }
    chunkCrc_.update(body);
    receivedBytes_ += body.size();
    ++chunks_;
    return true;
}

bool TransferReceiver::finishTransfer(const Bytes& body, std::string* error) {
    if (!inProgress_) {
        if (error != nullptr) {
            *error = "收到传输结束包，但没有正在进行的传输";
        }
        return true;
    }

    std::uint64_t declaredBytes = 0;
    std::uint32_t declaredCrc = 0;
    if (!decodeEnd(body, declaredBytes, declaredCrc, error)) {
        file_.close();
        inProgress_ = false;
        ++failedCount_;
        return true;
    }

    file_.flush();
    file_.close();

    lastResult_.bytes = receivedBytes_;
    lastResult_.chunks = chunks_;

    bool ok = true;
    std::string reason;
    if (receivedBytes_ != meta_.totalBytes) {
        ok = false;
        reason = "接收字节数与元数据不一致（收到 " + std::to_string(receivedBytes_) +
                 "，声明 " + std::to_string(meta_.totalBytes) + "）";
    } else if (declaredBytes != receivedBytes_) {
        ok = false;
        reason = "FILE_END 声明的字节数与实收不一致";
    } else if (declaredCrc != meta_.crc32) {
        ok = false;
        reason = "FILE_END 的 CRC32 与起始包声明不一致";
    } else if (chunkCrc_.value() != meta_.crc32) {
        // 逐块累积的 CRC32（在上面的 appendChunk 中计算）与发送端声明不符
        ok = false;
        reason = "逐块累积的 CRC32 与发送端声明不一致";
    }

    // 再读一次落盘文件做校验：确认"真正写到磁盘上的字节"也正确
    if (ok) {
        std::ifstream check = openInputFile(lastResult_.savedPath);
        if (!check) {
            ok = false;
            reason = "无法重新读取接收文件做校验";
        } else {
            Crc32 fileCrc;
            std::vector<char> buffer(64 * 1024);
            while (check) {
                check.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
                const std::streamsize got = check.gcount();
                if (got > 0) {
                    fileCrc.update(reinterpret_cast<const Byte*>(buffer.data()),
                                   static_cast<std::size_t>(got));
                }
            }
            lastResult_.crc32 = fileCrc.value();
            if (lastResult_.crc32 != meta_.crc32) {
                ok = false;
                reason = "整文件 CRC32 校验失败（文件可能损坏或被截断）";
            }
        }
    }

    inProgress_ = false;
    meta_ = Meta{};
    receivedBytes_ = 0;
    chunks_ = 0;
    chunkCrc_.reset();

    if (!ok) {
        lastResult_.ok = false;
        lastResult_.error = reason;
        ++failedCount_;
        if (error != nullptr) {
            *error = reason;
        }
        return true;
    }

    lastResult_.ok = true;
    ++completedCount_;
    ST_LOG_INFO(kLogModule, std::string("已接收 ") + kindToString(lastResult_.kind) + " " +
                                lastResult_.fileName + "（" +
                                std::to_string(lastResult_.bytes) + " 字节，" +
                                std::to_string(lastResult_.chunks) + " 块，CRC32 校验通过）");
    return true;
}

void TransferReceiver::reset() {
    if (file_.is_open()) {
        file_.close();
    }
    meta_ = Meta{};
    inProgress_ = false;
    receivedBytes_ = 0;
    chunks_ = 0;
    chunkCrc_.reset();
}

}  // namespace transfer
