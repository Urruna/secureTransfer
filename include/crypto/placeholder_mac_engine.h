// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/crypto/placeholder_mac_engine.h
//
//  WARNING: development-only placeholder implementation
//           这不是 CMAC，也不是任何标准 MAC 算法，不具备密码学强度。
//           它的作用只有一个：在第一部分的 CMAC 交付之前，让协议层的
//           握手、MAC 覆盖范围、篡改检测等逻辑可以端到端跑通与测试。
//
//           交付前必须替换为第一部分的 CMAC（见 include/crypto/mac_engine.h）。
//           替换点：AesCryptoProvider 构造时传入 CMAC 实现即可，其它代码不动。
// ============================================================================

#ifndef SECURETRANSFER_CRYPTO_PLACEHOLDER_MAC_ENGINE_H
#define SECURETRANSFER_CRYPTO_PLACEHOLDER_MAC_ENGINE_H

#include "crypto/mac_engine.h"

class PlaceholderMacEngine : public MacEngine {
public:
    const char* name() const override;
    bool isCryptographicallySecure() const override;

    MacTag compute(const Key128& key, const Bytes& data) override;
    bool verify(const Key128& key, const Bytes& data, const MacTag& tag) override;
};

#endif  // SECURETRANSFER_CRYPTO_PLACEHOLDER_MAC_ENGINE_H
