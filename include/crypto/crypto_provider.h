// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/crypto/crypto_provider.h
//
//  说明：密码算法与协议层之间的唯一接缝。
//
//        协议层（Packet / 握手 / 会话）只认识这个接口，不关心背后是
//        "自己写的 AES/CMAC" 还是别的实现：
//          * AesCryptoProvider    —— 使用第一部分的 AES 成果（真实算法）
//          * MockCryptoProvider   —— 开发期占位，协议联调用（不安全）
//          * 未来的 Part1CryptoProvider —— 第一部分交付 CMAC 后接入
//
//  约束：
//    1. aesCtrEncrypt / aesCtrDecrypt 必须支持任意长度（0 字节、1 字节、
//       非 16 的整数倍、1 MB），并且互为逆运算；
//    2. verifyCmac 必须使用常数时间比较；
//    3. 任何实现都不得在日志中输出密钥内容。
// ============================================================================

#ifndef SECURETRANSFER_CRYPTO_CRYPTO_PROVIDER_H
#define SECURETRANSFER_CRYPTO_CRYPTO_PROVIDER_H

#include "common/types.h"

class CryptoProvider {
public:
    virtual ~CryptoProvider() = default;

    /// 实现名称，用于日志与测试报告。
    virtual const char* name() const = 0;

    /// MAC 是否具备密码学强度。
    /// 当 CMAC 尚未交付、使用占位实现时必须返回 false，
    /// 上层据此打印"完整性保护暂不达标"的警告。
    virtual bool macIsCryptographicallySecure() const = 0;

    /// AES-CTR 加密（Nonce 作为初始计数器块）。
    virtual Bytes aesCtrEncrypt(const Key128& key, const Nonce& nonce,
                                const Bytes& plaintext) = 0;

    /// AES-CTR 解密。CTR 模式与加密是同一个运算。
    virtual Bytes aesCtrDecrypt(const Key128& key, const Nonce& nonce,
                                const Bytes& ciphertext) = 0;

    /// 计算消息认证码。
    virtual MacTag cmac(const Key128& key, const Bytes& data) = 0;

    /// 验证消息认证码（常数时间比较）。
    virtual bool verifyCmac(const Key128& key, const Bytes& data,
                            const MacTag& tag) = 0;
};

#endif  // SECURETRANSFER_CRYPTO_CRYPTO_PROVIDER_H
