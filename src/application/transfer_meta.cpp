// ============================================================================
//  SecureTransfer - 第三部分：应用层（文件 / 图像传输）
//  file: src/application/transfer_meta.cpp
// ============================================================================

#include "application/transfer_meta.h"

#include <algorithm>
#include <cctype>

#include "common/byte_buffer.h"

namespace transfer {

Bytes encodeMeta(const Meta& meta) {
    ByteWriter writer;
    writer.u8(meta.version);
    writer.u8(static_cast<Byte>(meta.kind));
    writer.u8(static_cast<Byte>(meta.mode));
    writer.tlv(meta.fileName);
    writer.u64(meta.totalBytes);
    writer.u32(meta.crc32);
    writer.u32(meta.inlineDataLength);
    return writer.bytes();
}

bool decodeMeta(const Bytes& body, Meta& meta, Bytes& payload, std::string* error) {
    ByteReader reader(body);

    Byte version = 0;
    Byte kind = 0;
    Byte mode = 0;
    if (!reader.u8(version) || !reader.u8(kind) || !reader.u8(mode)) {
        if (error != nullptr) {
            *error = "传输元数据不完整（缺少版本 / 类型 / 模式）";
        }
        return false;
    }
    if (version != kMetaVersion) {
        if (error != nullptr) {
            *error = "传输元数据版本不支持";
        }
        return false;
    }
    if (kind > static_cast<Byte>(Kind::kImage) || mode > static_cast<Byte>(Mode::kChunked)) {
        if (error != nullptr) {
            *error = "传输元数据的类型 / 模式取值非法";
        }
        return false;
    }

    Meta parsed;
    parsed.version = version;
    parsed.kind = static_cast<Kind>(kind);
    parsed.mode = static_cast<Mode>(mode);

    if (!reader.tlv(parsed.fileName) || !reader.u64(parsed.totalBytes) ||
        !reader.u32(parsed.crc32) || !reader.u32(parsed.inlineDataLength)) {
        if (error != nullptr) {
            *error = "传输元数据字段缺失";
        }
        return false;
    }
    if (!isSafeFileName(parsed.fileName)) {
        if (error != nullptr) {
            *error = "文件名非法或包含路径分隔符: " + parsed.fileName;
        }
        return false;
    }

    Bytes inlineData;
    if (parsed.mode == Mode::kSingleShot) {
        if (parsed.inlineDataLength != reader.remaining()) {
            if (error != nullptr) {
                *error = "单包传输的数据长度与元数据声明不一致";
            }
            return false;
        }
        if (!reader.raw(reader.remaining(), inlineData)) {
            if (error != nullptr) {
                *error = "单包传输的数据不完整";
            }
            return false;
        }
    } else if (reader.remaining() != 0) {
        if (error != nullptr) {
            *error = "分块传输的起始包不应携带数据";
        }
        return false;
    }

    meta = parsed;
    payload = inlineData;
    return true;
}

Bytes encodeEnd(std::uint64_t totalBytes, std::uint32_t crc32) {
    ByteWriter writer;
    writer.u64(totalBytes);
    writer.u32(crc32);
    return writer.bytes();
}

bool decodeEnd(const Bytes& body, std::uint64_t& totalBytes, std::uint32_t& crc32,
               std::string* error) {
    ByteReader reader(body);
    if (!reader.u64(totalBytes) || !reader.u32(crc32) || reader.remaining() != 0) {
        if (error != nullptr) {
            *error = "FILE_END 正文格式非法";
        }
        return false;
    }
    return true;
}

std::string baseName(const std::string& path) {
    const std::size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos) {
        return path;
    }
    return path.substr(slash + 1);
}

bool isSafeFileName(const std::string& name) {
    if (name.empty() || name.size() > 200) {
        return false;
    }
    if (name == "." || name == "..") {
        return false;
    }
    if (name.find('/') != std::string::npos || name.find('\\') != std::string::npos) {
        return false;
    }
    for (char c : name) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F) {
            return false;
        }
    }
    return true;
}

Kind kindFromExtension(const std::string& path) {
    const std::string name = baseName(path);
    const std::size_t dot = name.find_last_of('.');
    if (dot == std::string::npos) {
        return Kind::kFile;
    }
    std::string ext = name.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "bmp" || ext == "gif") {
        return Kind::kImage;
    }
    return Kind::kFile;
}

const char* kindToString(Kind kind) {
    return kind == Kind::kImage ? "图像" : "文件";
}

}  // namespace transfer
