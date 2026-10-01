// ============================================================================
//  SecureTransfer - 第一部分成果：AES-128
//  file: include/crypto/aes.h
//
//  来源：第一部分交付的 Windows/Visual Studio 工程 SecureTransfer
//        （原件存档于 reference/part1-aes-cmac/）。
//        导入到本工程时只做了两处调整，算法实现未改动：
//          1. 源文件编码由 GBK 转为 UTF-8；
//          2. include 路径由 "types.h" 改为 "common/types.h"（统一类型定义）。
//
//  接口与 projects/team_interfaces_original.md 的约定一致：
//        AES::encryptBlock(key, block)        —— 单个 16 字节分组加密（CMAC 使用）
//        AES::ctrXor(key, nonce, data, len)   —— CTR 模式原地加解密（TCP 业务使用）
//  另外暴露 C 风格函数 aes128_key_expand / aes128_encrypt_block，
//  供 CMAC 直接复用轮密钥，避免重复扩展。
// ============================================================================

#ifndef SECURETRANSFER_CRYPTO_AES_H
#define SECURETRANSFER_CRYPTO_AES_H

#include <cstddef>
#include <cstdint>

#include "common/types.h"

#define AES128_RK_SIZE 176

// 暴露底层 C 函数，供 CMAC 等高性能模块直接使用，避免重复扩展密钥
void aes128_key_expand(const uint8_t key[16], uint8_t rk[AES128_RK_SIZE]);
void aes128_encrypt_block(const uint8_t rk[AES128_RK_SIZE],
                          const uint8_t in[16],
                          uint8_t out[16]);

class AES {
public:
    // CMAC 用的单分组加密接口
    Bytes encryptBlock(const Key128& key, const Block128& block);

    // TCP 业务用 CTR 模式（原地加解密；CTR 加密与解密是同一个运算）
    void ctrXor(const Key128& key, const Block128& nonce,
                uint8_t* data, size_t len);
};

#endif  // SECURETRANSFER_CRYPTO_AES_H
