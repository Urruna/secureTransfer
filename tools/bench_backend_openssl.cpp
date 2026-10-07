// ============================================================================
//  SecureTransfer - 性能对比：OpenSSL 后端
//  file: tools/bench_backend_openssl.cpp
//
//  说明：OpenSSL 是唯一支持"运行时不改构建就禁用硬件加速"的库——
//        设置环境变量 OPENSSL_ia32cap=~0x200000200000000 即可让 EVP 走纯软件路径，
//        因此同一份二进制既能给"硬件加速"数据，也能给"纯软件"数据。
// ============================================================================

#include "bench_backend.h"

#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <cstdlib>
#include <string>

namespace bench {
namespace {

void opensslAesCtr(const Key128& key, const Nonce& nonce, Bytes& buffer, bool encrypt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outLength = 0;
    int finalLength = 0;
    if (encrypt) {
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(), nonce.data());
        EVP_EncryptUpdate(ctx, buffer.data(), &outLength, buffer.data(),
                          static_cast<int>(buffer.size()));
        EVP_EncryptFinal_ex(ctx, buffer.data() + outLength, &finalLength);
    } else {
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(), nonce.data());
        EVP_DecryptUpdate(ctx, buffer.data(), &outLength, buffer.data(),
                          static_cast<int>(buffer.size()));
        EVP_DecryptFinal_ex(ctx, buffer.data() + outLength, &finalLength);
    }
    EVP_CIPHER_CTX_free(ctx);
}

MacTag opensslCmac(const Key128& key, const Bytes& message) {
    MacTag tag{};
    CMAC_CTX* ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key.data(), key.size(), EVP_aes_128_cbc(), nullptr);
    CMAC_Update(ctx, message.data(), message.size());
    std::size_t outLength = 0;
    CMAC_Final(ctx, tag.data(), &outLength);
    CMAC_CTX_free(ctx);
    return tag;
}

/// 判断当前进程里的 OpenSSL 是否被要求禁用硬件指令（供报告标注用）。
std::string accelNote() {
    const char* ia32cap = std::getenv("OPENSSL_ia32cap");
    if (ia32cap != nullptr) {
        return std::string("纯软件（OPENSSL_ia32cap=") + ia32cap + "，已禁用 AES-NI）";
    }
    return "默认（本机支持 AES-NI 时使用硬件指令）";
}

}  // namespace

const Backend& opensslBackend() {
    static const Backend backend{
        "openssl",
        std::string(OPENSSL_VERSION_TEXT),  // 形如 "OpenSSL 3.6.5 29 Sep 2026"
        accelNote(),
        "EVP_aes_128_ctr + CMAC_CTX",
        &opensslAesCtr,
        &opensslCmac,
    };
    return backend;
}

}  // namespace bench
