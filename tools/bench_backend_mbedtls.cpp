// ============================================================================
//  SecureTransfer - 性能对比：Mbed TLS 后端
//  file: tools/bench_backend_mbedtls.cpp
//
//  说明：Mbed TLS 的 AES-NI 支持是**编译期开关**（MBEDTLS_AESNI_C），
//        没有运行时开关。所以"纯软件"数据来自另一份构建：
//          * 发行包（MSYS2 的 mingw-w64-x86_64-mbedtls）：默认带 AES-NI；
//          * 源码构建：把 MBEDTLS_AESNI_C 注释掉，用自定义 config 头编译出
//            libmbedcrypto_noaesni.a（见 docs/performance.md 的说明）。
//        本文件通过 MBEDTLS_AESNI_C 是否定义来判断当前链接的是哪一份，
//        从而在报告里正确标注"是否启用硬件加速"。
// ============================================================================

#include "bench_backend.h"

#include <mbedtls/aes.h>
#include <mbedtls/build_info.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>

#include <cstring>
#include <string>

namespace bench {
namespace {

void mbedtlsAesCtr(const Key128& key, const Nonce& nonce, Bytes& buffer, bool /*encrypt*/) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key.data(), 128);

    unsigned char counter[16];
    std::memcpy(counter, nonce.data(), sizeof(counter));
    unsigned char streamBlock[16] = {0};
    std::size_t offset = 0;
    // CTR 对称：加密与解密是同一个调用（一次性处理整个缓冲区）
    mbedtls_aes_crypt_ctr(&ctx, buffer.size(), &offset, counter, streamBlock, buffer.data(),
                          buffer.data());
    mbedtls_aes_free(&ctx);
}

MacTag mbedtlsCmac(const Key128& key, const Bytes& message) {
    MacTag tag{};
    const mbedtls_cipher_info_t* info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (info != nullptr) {
        mbedtls_cipher_cmac(info, key.data(), 128, message.data(), message.size(), tag.data());
    }
    return tag;
}

std::string accelNote() {
#if defined(MBEDTLS_AESNI_C)
    return "默认（库中编译进了 AES-NI，CPU 支持时启用）";
#else
    return "纯软件（源码构建：已禁用 MBEDTLS_AESNI_C）";
#endif
}

}  // namespace

const Backend& mbedtlsBackend() {
    static const Backend backend{
        "mbedtls",
        std::string("Mbed TLS ") + MBEDTLS_VERSION_STRING,
        accelNote(),
#if defined(MBEDTLS_AESNI_C)
        "发行包（MSYS2 mingw-w64-x86_64-mbedtls）",
#else
        "源码构建：自定义 config（注释掉 MBEDTLS_AESNI_C）",
#endif
        &mbedtlsAesCtr,
        &mbedtlsCmac,
    };
    return backend;
}

}  // namespace bench
