// ============================================================================
//  SecureTransfer - 性能对比：Botan 后端
//  file: tools/bench_backend_botan.cpp
//
//  说明：Botan 3（MSYS2 里是 3.13）要求 C++20，因此本文件所在的 target
//        会用 C++20 编译（其余代码仍是 C++17，互不影响）。
//
//        与 Mbed TLS 同理，Botan 的 AES-NI 由**构建时启用的模块**决定
//        （aes_ni / aes_vaes），没有公开的运行时开关，所以"纯软件"数据来自
//        源码构建（--disable-modules=aes_ni,aes_vaes，见 docs/performance.md）。
//        目标文件用宏 ST_BENCH_BOTAN_SOFT 区分这两份构建。
//
//  CTR 端序：必须用 CTR-BE（大端计数器），与自实现及 OpenSSL 的 CTR 一致；
//            正确性交叉验证会把这一点钉死（密文逐字节相同才算可比）。
// ============================================================================

#include "bench_backend.h"

#include <botan/cipher_mode.h>
#include <botan/mac.h>
#include <botan/version.h>

#include <string>

namespace bench {
namespace {

void botanAesCtr(const Key128& key, const Nonce& nonce, Bytes& buffer, bool /*encrypt*/) {
    auto cipher =
        Botan::Cipher_Mode::create_or_throw("AES-128/CTR-BE", Botan::Cipher_Dir::Encryption);
    cipher->set_key(key.data(), key.size());
    cipher->start(nonce.data(), nonce.size());
    cipher->process(buffer.data(), buffer.size());  // 就地一次性处理（含 start 的初始化开销）
}

MacTag botanCmac(const Key128& key, const Bytes& message) {
    MacTag tag{};
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
    mac->set_key(key.data(), key.size());
    mac->update(message.data(), message.size());
    mac->final(tag.data());
    return tag;
}

std::string accelNote() {
#if defined(ST_BENCH_BOTAN_SOFT)
    return "纯软件（源码构建：已禁用 aes_ni / aes_vaes 模块）";
#else
    return "默认（含 aes_ni / aes_vaes 模块，CPU 支持时启用硬件指令）";
#endif
}

}  // namespace

const Backend& botanBackend() {
    static const Backend backend{
        "botan",
        // short_version_string() 只给版本号，拼起来就是 "Botan 3.13.0"
        std::string("Botan ") + Botan::short_version_string(),
        accelNote(),
#if defined(ST_BENCH_BOTAN_SOFT)
        "源码构建：--minimized-build --enable-modules=aes,cmac,ctr,modes "
        "--disable-modules=aes_ni,aes_vaes",
#else
        "发行包（MSYS2 mingw-w64-x86_64-libbotan）",
#endif
        &botanAesCtr,
        &botanCmac,
    };
    return backend;
}

}  // namespace bench
