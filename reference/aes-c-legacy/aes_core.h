// ============================================================================
//  SecureTransfer - AES-128 核心算法（第一部分成果，由第二部分接入）
//  file: include/crypto/aes_core.h
//
//  来源：D:\圈圈\课程\算法设计与实验\AES\大作业\aes.h
//        导入时做了两件事：
//          1. 文件编码由 GBK 转为 UTF-8（原注释在 Ubuntu 下会显示乱码）；
//          2. 增加 extern "C" 保护，使 C++ 代码可以正常链接 C 编译的实现。
//
//  说明：本文件属于"第一部分：密码与安全机制"的成果，
//        第二部分只负责调用，不修改算法本身。
//
//  已知局限（由第一部分负责补齐）：
//        * 只有 AES-128 加密方向，没有单独的解密函数
//          （CTR 模式不需要，加密解密同为一次异或）；
//        * 没有 CMAC —— CMAC 需要在 aes_key_expand + aes_encrypt_block
//          之上另行实现（见 include/crypto/mac_engine.h）。
// ============================================================================

#ifndef SECURETRANSFER_CRYPTO_AES_CORE_H
#define SECURETRANSFER_CRYPTO_AES_CORE_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK 16      // AES 分组长度，固定 16 字节
#define AES_KEY 16        // AES-128 密钥长度，固定 16 字节
#define AES_RK_SIZE 176   // 扩展后的轮密钥总长度（11 轮 * 16 字节）

#ifdef __cplusplus
extern "C" {
#endif

// 第一步：用 16 字节密钥生成轮密钥 rk（之后所有加密都用 rk，不再直接用 key）
void aes_key_expand(const uint8_t key[AES_KEY], uint8_t rk[AES_RK_SIZE]);

// 第二步：加密一个分组（16 字节 in -> 16 字节 out）
// 【CMAC 只需要这一个函数 + aes_key_expand】
void aes_encrypt_block(const uint8_t rk[AES_RK_SIZE],
                       const uint8_t in[AES_BLOCK],
                       uint8_t out[AES_BLOCK]);

// 第三步：CTR 模式加解密任意长度数据（加密解密都调它，data 原地改变）
// nonce 必须 16 字节，同一个 rk 下 nonce 不能重复
// 【TCP 最终业务加密用这个】
// 注意：内部按大端自增整个 128 位计数器，因此一条长消息会占用连续多个
//      计数器值 —— 协议层据此设计了 Nonce 结构（见 docs/protocol.md §4）。
void aes_ctr_xor(const uint8_t rk[AES_RK_SIZE],
                 const uint8_t nonce[AES_BLOCK],
                 uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif  // SECURETRANSFER_CRYPTO_AES_CORE_H
