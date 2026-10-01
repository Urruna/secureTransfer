// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: src/crypto/mock_crypto_provider.cpp
// ============================================================================

#include "crypto/mock_crypto_provider.h"

#include <cstring>

namespace {

std::uint64_t splitmix64(std::uint64_t& state) {
    state += 0x9E3779B97F4A7C15ULL;
    std::uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/// 大端 128 位自增，与 aes.cpp 的 inc128_be 语义一致，
/// 这样才能真实反映"一条长消息会占用连续多个计数器值"的行为。
void incrementBigEndian(Byte* counter, std::size_t length) {
    for (std::size_t i = length; i-- > 0;) {
        counter[i] = static_cast<Byte>(counter[i] + 1);
        if (counter[i] != 0) {
            break;
        }
    }
}

/// 用计数器块生成 16 字节密钥流（占位算法，非 AES）。
Block128 keyStreamBlock(const Key128& key, const Block128& counter) {
    std::uint64_t state = 1469598103934665603ULL;
    for (Byte b : key) {
        state = (state ^ b) * 1099511628211ULL;
    }
    for (Byte b : counter) {
        state = (state ^ b) * 1099511628211ULL;
    }
    Block128 out{};
    for (std::size_t i = 0; i < out.size(); i += 8) {
        const std::uint64_t word = splitmix64(state);
        for (std::size_t j = 0; j < 8; ++j) {
            out[i + j] = static_cast<Byte>((word >> (8 * (7 - j))) & 0xFF);
        }
    }
    return out;
}

}  // namespace

const char* MockCryptoProvider::name() const {
    return "MockCryptoProvider(dev-only)";
}

bool MockCryptoProvider::macIsCryptographicallySecure() const {
    return false;
}

Bytes MockCryptoProvider::xorKeyStream(const Key128& key, const Nonce& nonce,
                                       const Bytes& input) {
    Bytes output = input;
    if (output.empty()) {
        return output;
    }

    Block128 counter = nonce;
    std::size_t offset = 0;
    while (offset < output.size()) {
        const Block128 stream = keyStreamBlock(key, counter);
        const std::size_t chunk = std::min<std::size_t>(16, output.size() - offset);
        for (std::size_t i = 0; i < chunk; ++i) {
            output[offset + i] = static_cast<Byte>(output[offset + i] ^ stream[i]);
        }
        offset += chunk;
        incrementBigEndian(counter.data(), counter.size());
    }
    return output;
}

Bytes MockCryptoProvider::aesCtrEncrypt(const Key128& key, const Nonce& nonce,
                                        const Bytes& plaintext) {
    return xorKeyStream(key, nonce, plaintext);
}

Bytes MockCryptoProvider::aesCtrDecrypt(const Key128& key, const Nonce& nonce,
                                        const Bytes& ciphertext) {
    return xorKeyStream(key, nonce, ciphertext);
}

MacTag MockCryptoProvider::cmac(const Key128& key, const Bytes& data) {
    return mac_.compute(key, data);
}

bool MockCryptoProvider::verifyCmac(const Key128& key, const Bytes& data,
                                    const MacTag& tag) {
    return mac_.verify(key, data, tag);
}
