// ============================================================================
//  SecureTransfer - 性能对比：后端接口
//  file: tools/bench_backend.h
//
//  说明：性能对比工具要比较"自实现"与多个库实现。这里把"一个实现"抽象成
//        Backend：只要提供 AES-128-CTR 与 CMAC 两个"一次性调用"函数即可，
//        其余的计时、表格、正确性交叉验证、汇总表都由 driver 统一处理，
//        这样新加一个库不会造成口径不一致。
//
//  调用口径（与已有报告保持一致，务必不要改）：
//    * AES-128-CTR：**一次性调用**——包含密钥扩展/上下文初始化，就地加解密；
//    * CMAC       ：**一次性调用**——包含密钥扩展与子密钥推导，输出 16 字节 tag；
//    * 同一份数据、同一把密钥、同一个 nonce，单线程。
//
//  ⚠ 课程要求 4：这些库只出现在本对比工具里；系统本体（alice/bob/st_*）
//     不链接任何密码学库，AES/CMAC 全部是第一部分的自己实现。
// ============================================================================

#ifndef SECURETRANSFER_TOOLS_BENCH_BACKEND_H
#define SECURETRANSFER_TOOLS_BENCH_BACKEND_H

#include <string>

#include "common/types.h"

namespace bench {

/// 一个参与对比的实现（自实现或某个库）。
struct Backend {
    std::string id;    ///< 短标识（用于 CSV 与倍率表的列名）：self / openssl / mbedtls / botan
    std::string name;  ///< 显示名，含版本号：如 "Mbed TLS 3.6.7"
    std::string accel; ///< 硬件加速说明：如 "AES-NI 已启用" / "纯软件（构建时禁用 AES-NI）"
    std::string note;  ///< 其它说明（构建方式等），可为空

    /// AES-128-CTR：一次性调用，就地加密/解密 buffer（CTR 对称，encrypt 仅用于口径对称）
    void (*aesCtr)(const Key128& key, const Nonce& nonce, Bytes& buffer, bool encrypt) = nullptr;

    /// CMAC：一次性调用，返回 16 字节 tag
    MacTag (*cmac)(const Key128& key, const Bytes& message) = nullptr;
};

/// 自实现（第一部分成果）——始终可用。
const Backend& selfBackend();

#if defined(ST_BENCH_WITH_OPENSSL)
/// OpenSSL：可用 `OPENSSL_ia32cap=~0x200000200000000` 在运行时禁用 AES-NI。
const Backend& opensslBackend();
#endif

#if defined(ST_BENCH_WITH_MBEDTLS)
/// Mbed TLS：AES-NI 是编译期开关（MBEDTLS_AESNI_C），所以"纯软件"要靠另建一份库。
const Backend& mbedtlsBackend();
#endif

#if defined(ST_BENCH_WITH_BOTAN)
/// Botan：AES-NI 由构建时启用的模块决定（aes_ni / aes_vaes）。
const Backend& botanBackend();
#endif

}  // namespace bench

#endif  // SECURETRANSFER_TOOLS_BENCH_BACKEND_H
