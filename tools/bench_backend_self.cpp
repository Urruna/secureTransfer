// ============================================================================
//  SecureTransfer - 性能对比：自实现后端（第一部分成果）
//  file: tools/bench_backend_self.cpp
// ============================================================================

#include "bench_backend.h"

#include "crypto/aes.h"
#include "crypto/cmac.h"

namespace bench {
namespace {

/// 一次性调用：与系统实际调用方式一致（每次做密钥扩展）
void selfAesCtr(const Key128& key, const Nonce& nonce, Bytes& buffer, bool /*encrypt*/) {
    AES aes;
    aes.ctrXor(key, nonce, buffer.data(), buffer.size());
}

MacTag selfCmac(const Key128& key, const Bytes& message) {
    CMAC cmac;
    return cmac.generate(key, message);
}

}  // namespace

const Backend& selfBackend() {
    static const Backend backend{
        "self",
        "自实现（本工程 AES-128-CTR + CMAC）",
        "纯软件（无硬件指令，C++ 查表实现）",
        "",
        &selfAesCtr,
        &selfCmac,
    };
    return backend;
}

}  // namespace bench
