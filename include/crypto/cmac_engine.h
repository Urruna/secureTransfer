// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/crypto/cmac_engine.h
//
//  说明：把第一部分的 CMAC 适配成协议层使用的 MacEngine 接口。
//
//  这是"第一部分成果"与"第二部分协议"之间唯一的粘合代码：
//  CMAC 的实现（src/crypto/cmac.cpp）一行都没有改，
//  协议层（Packet / 握手 / 会话）也只认识 MacEngine 接口。
//
//  经此适配后：
//        crypto.macIsCryptographicallySecure() == true
//        crypto.name() 中的 MAC 部分为 "CMAC(AES-128, RFC 4493)"
//  即程序的完整性保护由占位实现升级为真实密码学实现。
// ============================================================================

#ifndef SECURETRANSFER_CRYPTO_CMAC_ENGINE_H
#define SECURETRANSFER_CRYPTO_CMAC_ENGINE_H

#include "crypto/cmac.h"
#include "crypto/mac_engine.h"

class CmacEngine : public MacEngine {
public:
    const char* name() const override {
        return "CMAC(AES-128, RFC 4493)";
    }

    bool isCryptographicallySecure() const override {
        return true;
    }

    MacTag compute(const Key128& key, const Bytes& data) override {
        return cmac_.generate(key, data);
    }

    bool verify(const Key128& key, const Bytes& data, const MacTag& tag) override {
        return cmac_.verify(key, data, tag);
    }

private:
    CMAC cmac_;
};

#endif  // SECURETRANSFER_CRYPTO_CMAC_ENGINE_H
