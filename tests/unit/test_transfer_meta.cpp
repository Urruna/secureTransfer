// ============================================================================
//  SecureTransfer 测试
//  file: tests/unit/test_transfer_meta.cpp
//
//  说明：文件 / 图像传输的应用层单元测试：
//    * CRC32 标准已知值 + 分块累积与一次性计算一致；
//    * 传输元数据编解码往返、单包模式、非法输入拒绝；
//    * 文件名安全校验（防目录穿越）与类型推断；
//    * TransferReceiver 在不联网的情况下直接喂消息：
//        正常流程落盘并通过 CRC 校验；被篡改的 CRC 必须失败。
// ============================================================================

#include "test_util.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "application/crc32.h"
#include "application/file_transfer.h"
#include "application/transfer_meta.h"
#include "common/hex.h"

namespace {

const std::string kWorkDir = "/tmp/st_transfer_test";

void ensureWorkDir() {
    const int rc = std::system(("mkdir -p " + kWorkDir).c_str());
    (void)rc;
}

Bytes makeData(std::size_t size, std::uint32_t seed) {
    Bytes data(size);
    std::uint32_t state = seed ? seed : 1;
    for (std::size_t i = 0; i < size; ++i) {
        state = state * 1103515245u + 12345u;  // 确定性伪随机（只为可复现）
        data[i] = static_cast<Byte>((state >> 16) & 0xFF);
    }
    return data;
}

Bytes readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

}  // namespace

// 1. CRC32 标准已知值
ST_TEST_CASE("crc32: 标准已知值") {
    const Bytes check = stringToBytes("123456789");
    ST_CHECK_EQ(Crc32::compute(check), 0xCBF43926u);
    ST_CHECK_EQ(Crc32::compute(Bytes{}), 0x00000000u);

    // 分块累积 == 一次性计算
    const Bytes data = makeData(100 * 1024 + 7, 0x1234);
    Crc32 streamed;
    std::size_t offset = 0;
    while (offset < data.size()) {
        const std::size_t chunk = std::min<std::size_t>(4096, data.size() - offset);
        streamed.update(data.data() + offset, chunk);
        offset += chunk;
    }
    ST_CHECK_EQ(streamed.value(), Crc32::compute(data));
}

// 2. 元数据编解码往返（分块模式）
ST_TEST_CASE("transfer_meta: 分块模式往返") {
    transfer::Meta meta;
    meta.kind = transfer::Kind::kFile;
    meta.mode = transfer::Mode::kChunked;
    meta.fileName = "test_file_1MB.bin";
    meta.totalBytes = 1048576;
    meta.crc32 = 0xDEADBEEFu;
    meta.inlineDataLength = 0;

    const Bytes body = transfer::encodeMeta(meta);
    transfer::Meta parsed;
    Bytes payload;
    std::string error;
    ST_CHECK(transfer::decodeMeta(body, parsed, payload, &error));
    ST_CHECK_EQ(parsed.fileName, meta.fileName);
    ST_CHECK(parsed.kind == transfer::Kind::kFile);
    ST_CHECK(parsed.mode == transfer::Mode::kChunked);
    ST_CHECK_EQ(parsed.totalBytes, meta.totalBytes);
    ST_CHECK_EQ(parsed.crc32, meta.crc32);
    ST_CHECK(payload.empty());
}

// 3. 单包模式（元数据 + 数据）往返
ST_TEST_CASE("transfer_meta: 单包模式往返") {
    const Bytes image = makeData(1234, 0x77);
    transfer::Meta meta;
    meta.kind = transfer::Kind::kImage;
    meta.mode = transfer::Mode::kSingleShot;
    meta.fileName = "small.png";
    meta.totalBytes = image.size();
    meta.crc32 = Crc32::compute(image);
    meta.inlineDataLength = static_cast<std::uint32_t>(image.size());

    Bytes body = transfer::encodeMeta(meta);
    body.insert(body.end(), image.begin(), image.end());

    transfer::Meta parsed;
    Bytes payload;
    std::string error;
    ST_CHECK(transfer::decodeMeta(body, parsed, payload, &error));
    ST_CHECK(parsed.mode == transfer::Mode::kSingleShot);
    ST_CHECK(payload == image);
}

// 4. 非法输入必须被拒绝
ST_TEST_CASE("transfer_meta: 非法输入被拒绝") {
    transfer::Meta parsed;
    Bytes payload;
    std::string error;

    // 空正文
    ST_CHECK(!transfer::decodeMeta(Bytes{}, parsed, payload, &error));
    // 文件名带路径分隔符（目录穿越）
    transfer::Meta evil;
    evil.fileName = "../../etc/passwd";
    ST_CHECK(!transfer::decodeMeta(transfer::encodeMeta(evil), parsed, payload, &error));
    // 版本不对
    Bytes badVersion = transfer::encodeMeta(transfer::Meta{});
    badVersion[0] = 99;
    ST_CHECK(!transfer::decodeMeta(badVersion, parsed, payload, &error));
    // 声明单包但数据长度对不上
    transfer::Meta single;
    single.mode = transfer::Mode::kSingleShot;
    single.fileName = "a.png";
    single.inlineDataLength = 100;
    Bytes truncated = transfer::encodeMeta(single);
    ST_CHECK(!transfer::decodeMeta(truncated, parsed, payload, &error));

    // 文件名安全校验
    ST_CHECK(transfer::isSafeFileName("ok.txt"));
    ST_CHECK(!transfer::isSafeFileName(""));
    ST_CHECK(!transfer::isSafeFileName(".."));
    ST_CHECK(!transfer::isSafeFileName("a/b.txt"));
    ST_CHECK(!transfer::isSafeFileName("a\\b.txt"));

    // 类型推断与路径取基本名
    ST_CHECK(transfer::kindFromExtension("/tmp/x/photo.PNG") == transfer::Kind::kImage);
    ST_CHECK(transfer::kindFromExtension("photo.jpeg") == transfer::Kind::kImage);
    ST_CHECK(transfer::kindFromExtension("data.bin") == transfer::Kind::kFile);
    ST_CHECK_EQ(transfer::baseName("/a/b/c.txt"), std::string("c.txt"));
}

// 5. FILE_END 编解码
ST_TEST_CASE("transfer_meta: FILE_END 往返") {
    const Bytes body = transfer::encodeEnd(1048576, 0x0BADF00Du);
    std::uint64_t bytes = 0;
    std::uint32_t crc = 0;
    std::string error;
    ST_CHECK(transfer::decodeEnd(body, bytes, crc, &error));
    ST_CHECK_EQ(bytes, 1048576u);
    ST_CHECK_EQ(crc, 0x0BADF00Du);

    // 长度不对必须拒绝
    ST_CHECK(!transfer::decodeEnd(Bytes{0x01, 0x02}, bytes, crc, &error));
}

// 6. TransferReceiver：直接喂消息（不联网），落盘 + CRC 校验
ST_TEST_CASE("transfer_receiver: 分块接收并校验通过") {
    const Bytes data = makeData(200 * 1024 + 37, 0x5A5A);  // 跨 4 个 64 KiB 块
    transfer::TransferReceiver receiver(kWorkDir);

    transfer::Meta meta;
    meta.kind = transfer::Kind::kFile;
    meta.mode = transfer::Mode::kChunked;
    meta.fileName = "unit_chunked.bin";
    meta.totalBytes = data.size();
    meta.crc32 = Crc32::compute(data);

    std::string error;
    ST_CHECK(receiver.handle(MessageType::kFileStart, transfer::encodeMeta(meta), &error));
    ST_CHECK(receiver.inProgress());

    std::size_t offset = 0;
    while (offset < data.size()) {
        const std::size_t chunk = std::min<std::size_t>(transfer::kChunkSize, data.size() - offset);
        const Bytes piece(data.begin() + static_cast<std::ptrdiff_t>(offset),
                          data.begin() + static_cast<std::ptrdiff_t>(offset + chunk));
        ST_CHECK(receiver.handle(MessageType::kFileChunk, piece, &error));
        offset += chunk;
    }
    ST_CHECK(receiver.handle(MessageType::kFileEnd,
                             transfer::encodeEnd(data.size(), meta.crc32), &error));
    ST_CHECK(!receiver.inProgress());

    const transfer::ReceiveResult& result = receiver.lastResult();
    ST_CHECK(result.ok);
    ST_CHECK_EQ(result.bytes, data.size());
    ST_CHECK_EQ(result.crc32, meta.crc32);
    ST_CHECK(readFile(result.savedPath) == data);  // 落盘内容逐字节一致
    ST_CHECK_EQ(receiver.completedCount(), 1u);
    ST_CHECK_EQ(receiver.failedCount(), 0u);
}

// 7. 被篡改的 CRC / 截断的文件必须被发现
ST_TEST_CASE("transfer_receiver: CRC 不一致必须失败") {
    const Bytes data = makeData(1024, 0x1111);
    transfer::TransferReceiver receiver(kWorkDir);

    transfer::Meta meta;
    meta.kind = transfer::Kind::kFile;
    meta.mode = transfer::Mode::kChunked;
    meta.fileName = "unit_badcrc.bin";
    meta.totalBytes = data.size();
    meta.crc32 = Crc32::compute(data);

    std::string error;
    ST_CHECK(receiver.handle(MessageType::kFileStart, transfer::encodeMeta(meta), &error));
    ST_CHECK(receiver.handle(MessageType::kFileChunk, data, &error));
    // 故意给一个错误的 CRC32
    ST_CHECK(receiver.handle(MessageType::kFileEnd,
                             transfer::encodeEnd(data.size(), meta.crc32 ^ 0xFFFFFFFFu), &error));
    ST_CHECK(!receiver.lastResult().ok);
    ST_CHECK(!error.empty());
    ST_CHECK_EQ(receiver.failedCount(), 1u);
}

// 8. 单包图像直接落盘
ST_TEST_CASE("transfer_receiver: 单包图像接收") {
    const Bytes image = makeData(4096, 0x2222);
    transfer::TransferReceiver receiver(kWorkDir);

    transfer::Meta meta;
    meta.kind = transfer::Kind::kImage;
    meta.mode = transfer::Mode::kSingleShot;
    meta.fileName = "unit_small.png";
    meta.totalBytes = image.size();
    meta.crc32 = Crc32::compute(image);
    meta.inlineDataLength = static_cast<std::uint32_t>(image.size());

    Bytes body = transfer::encodeMeta(meta);
    body.insert(body.end(), image.begin(), image.end());

    std::string error;
    ST_CHECK(receiver.handle(MessageType::kImage, body, &error));
    ST_CHECK(receiver.lastResult().ok);
    ST_CHECK(receiver.lastResult().singleShot);
    ST_CHECK(readFile(receiver.lastResult().savedPath) == image);
}

// 9. 非传输消息不应被接收器消费
ST_TEST_CASE("transfer_receiver: 非传输消息返回 false") {
    transfer::TransferReceiver receiver(kWorkDir);
    std::string error;
    ST_CHECK(!receiver.handle(MessageType::kData, stringToBytes("hello"), &error));
    ST_CHECK(!receiver.handle(MessageType::kClose, Bytes{}, &error));
    // 没有开始就收到数据块：属于传输流程但状态非法，返回 true 并给出错误
    ST_CHECK(receiver.handle(MessageType::kFileChunk, stringToBytes("x"), &error));
    ST_CHECK(!error.empty());
}

int main() {
    ensureWorkDir();
    return ::testutil::runAll("transfer_meta");
}
