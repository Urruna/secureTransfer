// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/crypto/mac_engine.h
//
//  说明：MAC 算法的接缝。第一部分交付 CMAC 后，只需要实现本接口并注入
//        AesCryptoProvider，协议层与测试代码完全不用改动。
//
//        当前状态：CMAC 仍在第一部分开发中，仓库内提供
//        PlaceholderMacEngine 作为占位实现（明确标注不具备密码学强度）。
// ============================================================================

#ifndef SECURETRANSFER_CRYPTO_MAC_ENGINE_H
#define SECURETRANSFER_CRYPTO_MAC_ENGINE_H

#include "common/types.h"

class MacEngine {
public:
    virtual ~MacEngine() = default;

    /// 算法名称，用于日志与测试报告。
    virtual const char* name() const = 0;

    /// 是否具备密码学强度（占位实现必须返回 false）。
    virtual bool isCryptographicallySecure() const = 0;

    virtual MacTag compute(const Key128& key, const Bytes& data) = 0;

    virtual bool verify(const Key128& key, const Bytes& data, const MacTag& tag) = 0;
};

#endif  // SECURETRANSFER_CRYPTO_MAC_ENGINE_H
