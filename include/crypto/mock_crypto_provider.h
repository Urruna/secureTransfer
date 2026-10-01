// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/crypto/mock_crypto_provider.h
//
//  WARNING: development-only mock implementation
//           AES 与 MAC 都是占位实现，不具备任何密码学强度，
//           仅用于在真实算法到位之前把协议层跑通。
//           正式演示请使用 AesCryptoProvider（真实 AES-CTR）。
// ============================================================================

#ifndef SECURETRANSFER_CRYPTO_MOCK_CRYPTO_PROVIDER_H
#define SECURETRANSFER_CRYPTO_MOCK_CRYPTO_PROVIDER_H

#include "crypto/crypto_provider.h"
#include "crypto/placeholder_mac_engine.h"

class MockCryptoProvider : public CryptoProvider {
public:
    const char* name() const override;
    bool macIsCryptographicallySecure() const override;

    Bytes aesCtrEncrypt(const Key128& key, const Nonce& nonce,
                        const Bytes& plaintext) override;
    Bytes aesCtrDecrypt(const Key128& key, const Nonce& nonce,
                        const Bytes& ciphertext) override;

    MacTag cmac(const Key128& key, const Bytes& data) override;
    bool verifyCmac(const Key128& key, const Bytes& data, const MacTag& tag) override;

private:
    Bytes xorKeyStream(const Key128& key, const Nonce& nonce, const Bytes& input);

    PlaceholderMacEngine mac_;
};

#endif  // SECURETRANSFER_CRYPTO_MOCK_CRYPTO_PROVIDER_H
