// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: src/crypto/aes_crypto_provider.cpp
// ============================================================================

#include "crypto/aes_crypto_provider.h"

#include <cstring>

#include "common/log.h"
#include "crypto/aes.h"

namespace {

const char* const kLogModule = "Crypto";

}  // namespace

AesCryptoProvider::AesCryptoProvider(MacEngine* macEngine)
    : cmac_(), placeholderMac_(), mac_(macEngine != nullptr ? macEngine : &cmac_) {
    if (!mac_->isCryptographicallySecure()) {
        ST_LOG_WARN(kLogModule,
                    std::string("当前 MAC 实现为占位实现（") + mac_->name() +
                        "）：握手、密钥分发与防重放均按真实协议运行，"
                        "但消息完整性保护暂不具备密码学强度。"
                        "默认实现（第一部分 CMAC）不受此影响。");
    }
}

AesCryptoProvider::~AesCryptoProvider() = default;

const char* AesCryptoProvider::name() const {
    return "AesCryptoProvider(AES-128-CTR)";
}

bool AesCryptoProvider::macIsCryptographicallySecure() const {
    return mac_->isCryptographicallySecure();
}

const char* AesCryptoProvider::macEngineName() const {
    return mac_->name();
}

Bytes AesCryptoProvider::ctrXor(const Key128& key, const Nonce& nonce,
                                const Bytes& input) {
    Bytes output = input;
    if (output.empty()) {
        return output;
    }

    AES aes;
    aes.ctrXor(key, nonce, output.data(), output.size());
    return output;
}

Bytes AesCryptoProvider::aesCtrEncrypt(const Key128& key, const Nonce& nonce,
                                       const Bytes& plaintext) {
    return ctrXor(key, nonce, plaintext);
}

Bytes AesCryptoProvider::aesCtrDecrypt(const Key128& key, const Nonce& nonce,
                                       const Bytes& ciphertext) {
    return ctrXor(key, nonce, ciphertext);
}

MacTag AesCryptoProvider::cmac(const Key128& key, const Bytes& data) {
    return mac_->compute(key, data);
}

bool AesCryptoProvider::verifyCmac(const Key128& key, const Bytes& data,
                                   const MacTag& tag) {
    return mac_->verify(key, data, tag);
}
