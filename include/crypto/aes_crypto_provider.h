// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/crypto/aes_crypto_provider.h
//
//  说明：使用第一部分 AES 成果的真实 CTR 实现。
//
//        * AES-CTR：第一部分自实现的真实算法（src/crypto/aes.cpp），
//                   已用 FIPS-197 与 NIST SP 800-38A 向量验证；
//        * MAC    ：默认使用**第一部分的 CMAC**（src/crypto/cmac.cpp，
//                   RFC 4493 的 4 条标准向量已验证），
//                   通过 CmacEngine 适配到 MacEngine 接口。
//
//  算法仍然可以替换：构造时传入其它 MacEngine 即可
//  （例如 PlaceholderMacEngine，用于演示"算法与协议解耦"），
//  协议层、测试、应用代码都不需要修改。
// ============================================================================

#ifndef SECURETRANSFER_CRYPTO_AES_CRYPTO_PROVIDER_H
#define SECURETRANSFER_CRYPTO_AES_CRYPTO_PROVIDER_H

#include "crypto/cmac_engine.h"
#include "crypto/crypto_provider.h"
#include "crypto/mac_engine.h"
#include "crypto/placeholder_mac_engine.h"

class AesCryptoProvider : public CryptoProvider {
public:
    /// @param macEngine MAC 实现；传 nullptr 时使用**第一部分的 CMAC**
    ///                  （RFC 4493 标准向量已验证）。
    ///                  仅在需要演示算法可替换性时，才显式传入
    ///                  PlaceholderMacEngine。
    explicit AesCryptoProvider(MacEngine* macEngine = nullptr);
    ~AesCryptoProvider() override;

    const char* name() const override;
    bool macIsCryptographicallySecure() const override;

    /// 当前使用的 MAC 实现名称（用于启动时打印/报告中记录）。
    const char* macEngineName() const;

    Bytes aesCtrEncrypt(const Key128& key, const Nonce& nonce,
                        const Bytes& plaintext) override;
    Bytes aesCtrDecrypt(const Key128& key, const Nonce& nonce,
                        const Bytes& ciphertext) override;

    MacTag cmac(const Key128& key, const Bytes& data) override;
    bool verifyCmac(const Key128& key, const Bytes& data, const MacTag& tag) override;

private:
    Bytes ctrXor(const Key128& key, const Nonce& nonce, const Bytes& input);

    CmacEngine cmac_;
    PlaceholderMacEngine placeholderMac_;
    MacEngine* mac_;
};

#endif  // SECURETRANSFER_CRYPTO_AES_CRYPTO_PROVIDER_H
