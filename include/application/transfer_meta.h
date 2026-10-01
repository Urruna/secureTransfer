// ============================================================================
//  SecureTransfer - 第三部分：应用层（文件 / 图像传输）
//  file: include/application/transfer_meta.h
//
//  说明：文件 / 图像传输的元数据格式与解析。
//
//  所有传输消息都装在一个普通的安全数据包里（`SecureSession::sendMessage`），
//  因此**自动获得** AES-CTR 加密、CMAC 完整性保护、Sequence 防重放与方向校验，
//  应用层不需要再碰任何密码学 API。
//
//  正文格式（全部用大端；TLV 见 common/byte_buffer.h）：
//
//    START / IMAGE(单包) 正文：
//        [u8  版本 = 1]
//        [u8  kind   0 = 普通文件, 1 = 图像]
//        [u8  mode   0 = 单包传输（正文后紧跟数据）, 1 = 分块传输（后续跟 FILE_CHUNK）]
//        [tlv 文件名（UTF-8，只取基本名，禁止路径分隔符）]
//        [u64 文件总字节数]
//        [u32 整文件 CRC32]
//        [u32 数据字节数]            // mode = 0 时有效，其它情况为 0
//
//    FILE_CHUNK 正文：就是这一块的原始字节（偏移由到达顺序决定，
//                     顺序与重放由协议的 Sequence 保证）
//
//    FILE_END 正文：
//        [u64 已发送/已接收的总字节数]
//        [u32 整文件 CRC32]
// ============================================================================

#ifndef SECURETRANSFER_APPLICATION_TRANSFER_META_H
#define SECURETRANSFER_APPLICATION_TRANSFER_META_H

#include <cstdint>
#include <string>

#include "common/types.h"

namespace transfer {

/// 分块大小：64 KiB。协议单包正文上限约 1 MiB，留足余量。
constexpr std::size_t kChunkSize = 64 * 1024;

/// 元数据版本号。
constexpr Byte kMetaVersion = 1;

enum class Kind : Byte {
    kFile = 0,   ///< 普通文件
    kImage = 1   ///< 图像
};

enum class Mode : Byte {
    kSingleShot = 0,  ///< 元数据 + 数据放在同一个包里（仅用于小图像）
    kChunked = 1      ///< 后续用 FILE_CHUNK 分块传输
};

struct Meta {
    Byte version = kMetaVersion;
    Kind kind = Kind::kFile;
    Mode mode = Mode::kChunked;
    std::string fileName;
    std::uint64_t totalBytes = 0;
    std::uint32_t crc32 = 0;
    std::uint32_t inlineDataLength = 0;  ///< mode == kSingleShot 时正文里数据部分的长度
};

/// 编码 START / IMAGE 的元数据部分（不含数据）。
Bytes encodeMeta(const Meta& meta);

/// 解析 START / IMAGE 的正文：解析出元数据，并把剩余数据部分交给 payload。
/// @param body     收到的正文
/// @param meta     输出：元数据
/// @param payload  输出：正文里携带的数据（分块传输时为空）
/// @param error    失败原因
bool decodeMeta(const Bytes& body, Meta& meta, Bytes& payload, std::string* error);

/// 编码 FILE_END 正文。
Bytes encodeEnd(std::uint64_t totalBytes, std::uint32_t crc32);

/// 解析 FILE_END 正文。
bool decodeEnd(const Bytes& body, std::uint64_t& totalBytes, std::uint32_t& crc32,
               std::string* error);

/// 从路径中取出基本文件名（去掉目录部分），用于在元数据里传名字。
std::string baseName(const std::string& path);

/// 校验文件名是否可以安全落盘（禁止路径分隔符、空名、过长、"." / ".."）。
bool isSafeFileName(const std::string& name);

/// 根据扩展名猜测类型（.png/.jpg/.jpeg/.bmp/.gif → 图像）。
Kind kindFromExtension(const std::string& path);

const char* kindToString(Kind kind);

}  // namespace transfer

#endif  // SECURETRANSFER_APPLICATION_TRANSFER_META_H
