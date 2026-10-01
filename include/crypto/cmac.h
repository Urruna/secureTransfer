// ============================================================================
//  SecureTransfer - 第一部分成果：CMAC（RFC 4493，基于 AES-128）
//  file: include/crypto/cmac.h
//
//  来源：第一部分交付的 Windows/Visual Studio 工程 SecureTransfer
//        （原件存档于 reference/part1-aes-cmac/）。
//        导入时只调整了编码与 include 路径，算法实现未改动。
//
//  接口与 projects/team_interfaces_original.md 的约定一致：
//        CMAC::generate(key, message)         —— 生成 16 字节标签
//        CMAC::verify(key, message, tag)      —— 验证（常数时间比较）
//
//  标准向量验证：RFC 4493 的 4 条向量（空消息 / 16B / 40B / 64B），
//  见 tests/unit/test_aes_cmac.cpp。
// ============================================================================

#ifndef SECURETRANSFER_CRYPTO_CMAC_H
#define SECURETRANSFER_CRYPTO_CMAC_H

#include "common/types.h"

class CMAC {
public:
    MacTag generate(const Key128& key, const Bytes& message);
    bool   verify(const Key128& key, const Bytes& message, const MacTag& tag);

private:
    static Block128 xorBlock(const Block128& a, const Block128& b);
    static Block128 leftShift(const Block128& in);
    static bool     msbSet(const Block128& in);
    static void     deriveSubkeys(const Key128& key, Block128& K1, Block128& K2);
    static Block128 padBlock(const uint8_t* data, size_t len);
};

#endif  // SECURETRANSFER_CRYPTO_CMAC_H
