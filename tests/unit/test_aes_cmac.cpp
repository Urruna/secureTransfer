// ============================================================================
//  SecureTransfer 测试
//  file: tests/unit/test_aes_cmac.cpp
//
//  说明：第一部分成果（AES-128 + CMAC）的标准向量回归测试。
//        这是课程要求 3「使用标准数据进行算法正确性测试」的直接证据，
//        也保证第二部分的数据通道确实建立在正确实现的算法之上。
//
//  覆盖：
//    1. FIPS-197 附录 B 单分组向量             aes128_encrypt_block / AES::encryptBlock
//    2. NIST SP 800-38A F.5.1 CTR 向量         AES::ctrXor
//    3. RFC 4493 的 4 条 CMAC 标准向量          CMAC::generate
//    4. CTR 往返（含中文与二进制）               AES::ctrXor
//    5. MacEngine 适配（CmacEngine / 占位实现）  协议层接缝
//    6. CryptoProvider 默认使用真实 CMAC        AesCryptoProvider
// ============================================================================

#include "test_util.h"

#include <string>

#include "common/hex.h"
#include "crypto/aes.h"
#include "crypto/aes_crypto_provider.h"
#include "crypto/cmac.h"
#include "crypto/cmac_engine.h"
#include "crypto/placeholder_mac_engine.h"

namespace {

Key128 keyFromHex(const std::string& hex) {
    Key128 key{};
    if (!fromHex(hex, key)) {
        throw ::testutil::Failure("测试密钥解析失败: " + hex);
    }
    return key;
}

Bytes bytesFromHex(const std::string& hex) {
    Bytes data;
    if (!fromHex(hex, data)) {
        throw ::testutil::Failure("测试数据解析失败: " + hex);
    }
    return data;
}

/// RFC 4493 / FIPS-197 / SP 800-38A 通用的测试密钥
const char* const kRfcKey = "2b7e151628aed2a6abf7158809cf4f3c";

}  // namespace

// 1. FIPS-197 单分组标准向量
ST_TEST_CASE("aes: FIPS-197 单分组标准向量") {
    const Key128 key = keyFromHex("000102030405060708090a0b0c0d0e0f");
    const Bytes plaintext =
        bytesFromHex("00112233445566778899aabbccddeeff");

    // 底层 C 接口
    uint8_t roundKeys[AES128_RK_SIZE];
    uint8_t out[16];
    aes128_key_expand(key.data(), roundKeys);
    aes128_encrypt_block(roundKeys, plaintext.data(), out);
    ST_CHECK_EQ(toHex(out, 16), std::string("69c4e0d86a7b0430d8cdb78070b4c55a"));

    // C++ 类接口（team_interfaces_original.md 约定的 AES::encryptBlock）
    AES aes;
    Block128 block{};
    std::copy(plaintext.begin(), plaintext.end(), block.begin());
    const Bytes cipher = aes.encryptBlock(key, block);
    ST_CHECK_EQ(toHex(cipher), std::string("69c4e0d86a7b0430d8cdb78070b4c55a"));
}

// 2. NIST SP 800-38A F.5.1（CTR-AES128）标准向量
ST_TEST_CASE("aes: NIST SP 800-38A CTR 标准向量") {
    const Key128 key = keyFromHex(kRfcKey);
    Block128 counter{};
    ST_CHECK(fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", counter));

    Bytes data =
        bytesFromHex("6bc1bee22e409f96e93d7e117393172a"
                     "ae2d8a571e03ac9c9eb76fac45af8e51");

    AES aes;
    aes.ctrXor(key, counter, data.data(), data.size());
    ST_CHECK_EQ(toHex(data),
                std::string("874d6191b620e3261bef6864990db6ce"
                            "9806f66b7970fdff8617187bb9fffdff"));
}

// 3. RFC 4493 的 4 条 CMAC 标准向量
ST_TEST_CASE("cmac: RFC 4493 标准向量") {
    const Key128 key = keyFromHex(kRfcKey);
    CMAC cmac;

    struct Vector {
        const char* name;
        const char* messageHex;
        const char* expectedTagHex;
    };
    const Vector vectors[] = {
        {"空消息", "", "bb1d6929e95937287fa37d129b756746"},
        {"16 字节（1 个分组）", "6bc1bee22e409f96e93d7e117393172a",
         "070a16b46b4d4144f79bdd9dd04a287c"},
        {"40 字节（不完整末块）",
         "6bc1bee22e409f96e93d7e117393172a"
         "ae2d8a571e03ac9c9eb76fac45af8e51"
         "30c81c46a35ce411",
         "dfa66747de9ae63030ca32611497c827"},
        {"64 字节（完整末块）",
         "6bc1bee22e409f96e93d7e117393172a"
         "ae2d8a571e03ac9c9eb76fac45af8e51"
         "30c81c46a35ce411e5fbc1191a0a52ef"
         "f69f2445df4f9b17ad2b417be66c3710",
         "51f0bebf7e3b9d92fc49741779363cfe"},
    };

    for (const Vector& vector : vectors) {
        const Bytes message = bytesFromHex(vector.messageHex);
        const MacTag tag = cmac.generate(key, message);
        ST_CHECK_EQ(toHex(tag), std::string(vector.expectedTagHex));
        ST_CHECK(cmac.verify(key, message, tag));
    }
}

// 4. CMAC 的验证语义：改一个字节必须失败
ST_TEST_CASE("cmac: 验证语义与篡改检测") {
    const Key128 key = keyFromHex(kRfcKey);
    const Key128 otherKey = keyFromHex("00112233445566778899aabbccddeeff");
    CMAC cmac;

    const Bytes message = bytesFromHex("6bc1bee22e409f96e93d7e117393172a");
    const MacTag tag = cmac.generate(key, message);
    ST_CHECK(cmac.verify(key, message, tag));

    // 换密钥
    ST_CHECK(!cmac.verify(otherKey, message, tag));

    // 改消息
    Bytes tampered = message;
    tampered[0] = static_cast<uint8_t>(tampered[0] ^ 0xFF);
    ST_CHECK(!cmac.verify(key, tampered, tag));

    // 改标签
    MacTag badTag = tag;
    badTag[15] = static_cast<uint8_t>(badTag[15] ^ 0x01);
    ST_CHECK(!cmac.verify(key, message, badTag));
}

// 5. AES-CTR 往返（含中文 UTF-8 与二进制）
ST_TEST_CASE("aes: CTR 往返与任意长度") {
    const Key128 key = keyFromHex("000102030405060708090a0b0c0d0e0f");
    Block128 nonce{};
    ST_CHECK(fromHex("0102030405060708090a0b0c0d0e0f10", nonce));
    AES aes;

    const std::string messages[] = {
        "Hello Bob!",
        "A secure message between Alice and Bob.",
        "Transfer #1024: Alice->Bob, amount=500.00 USD; status=OK! (check: 9f8e7d6c)",
        "你好，Bob，这是一次安全通信测试。",
        "",
    };

    for (const std::string& text : messages) {
        const Bytes plaintext = stringToBytes(text);
        Bytes buffer = plaintext;
        aes.ctrXor(key, nonce, buffer.data(), buffer.size());
        if (!plaintext.empty()) {
            ST_CHECK(buffer != plaintext);  // 确实被加密
        }
        aes.ctrXor(key, nonce, buffer.data(), buffer.size());
        ST_CHECK(buffer == plaintext);
    }

    // 非 16 整数倍长度：37 字节二进制
    Bytes binary(37);
    for (std::size_t i = 0; i < binary.size(); ++i) {
        binary[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    Bytes buffer = binary;
    aes.ctrXor(key, nonce, buffer.data(), buffer.size());
    ST_CHECK(buffer != binary);
    aes.ctrXor(key, nonce, buffer.data(), buffer.size());
    ST_CHECK(buffer == binary);
}

// 6. CmacEngine：把第一部分的 CMAC 接到协议层的 MacEngine 接口
ST_TEST_CASE("cmac_engine: 适配后与直接调用 CMAC 完全一致") {
    const Key128 key = keyFromHex(kRfcKey);
    CMAC cmac;
    CmacEngine engine;

    const Bytes message =
        bytesFromHex("6bc1bee22e409f96e93d7e117393172a"
                     "ae2d8a571e03ac9c9eb76fac45af8e51");

    ST_CHECK(engine.compute(key, message) == cmac.generate(key, message));
    ST_CHECK(engine.verify(key, message, cmac.generate(key, message)));
    ST_CHECK(engine.isCryptographicallySecure());
    ST_CHECK(std::string(engine.name()).find("CMAC") != std::string::npos);
}

// 7. CryptoProvider 默认使用第一部分的真实 CMAC
ST_TEST_CASE("crypto_provider: 默认 MAC 为真实 CMAC") {
    AesCryptoProvider provider;  // 不传参数 => 默认使用 CmacEngine
    ST_CHECK(provider.macIsCryptographicallySecure());
    ST_CHECK(std::string(provider.macEngineName()).find("CMAC") != std::string::npos);

    const Key128 key = keyFromHex(kRfcKey);
    const Bytes data = stringToBytes("Alice -> Bob: transfer 100 USD");
    const MacTag tag = provider.cmac(key, data);
    ST_CHECK(provider.verifyCmac(key, data, tag));

    Bytes tampered = data;
    tampered[0] = static_cast<uint8_t>(tampered[0] ^ 0xFF);
    ST_CHECK(!provider.verifyCmac(key, tampered, tag));
}

// 8. 占位实现仍可显式选用（用于演示"算法可替换"）
ST_TEST_CASE("crypto_provider: 仍可显式切换到占位 MAC") {
    PlaceholderMacEngine placeholder;
    AesCryptoProvider provider(&placeholder);
    ST_CHECK(!provider.macIsCryptographicallySecure());

    const Key128 key = keyFromHex(kRfcKey);
    const Bytes data = stringToBytes("data");
    ST_CHECK(provider.verifyCmac(key, data, provider.cmac(key, data)));
}

// 9. 大消息（1 MiB，协议单包上限附近）上的 CMAC 一致性
ST_TEST_CASE("cmac: 1 MiB 数据仍然正确") {
    const Key128 key = keyFromHex(kRfcKey);
    CMAC cmac;
    Bytes message(1024u * 1024u, 0x5A);

    const MacTag first = cmac.generate(key, message);
    const MacTag second = cmac.generate(key, message);
    ST_CHECK(first == second);
    ST_CHECK(cmac.verify(key, message, first));

    message[message.size() - 1] = static_cast<uint8_t>(message.back() ^ 0x01);
    ST_CHECK(!cmac.verify(key, message, first));
}

int main() {
    return ::testutil::runAll("aes_cmac");
}
