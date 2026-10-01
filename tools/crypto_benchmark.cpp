// ============================================================================
//  SecureTransfer - 密码算法性能对比（自实现 vs 库实现）
//  file: tools/crypto_benchmark.cpp
//
//  对应课程要求 5 / project_q1.md §10：
//      "将自己的密码算法实现与库文件或别人的代码实现进行全面的性能对比"
//      数据规模：1 KB / 64 KB / 1 MB / 10 MB / 100 MB
//      记录：加密时间、解密时间、吞吐率
//
//  ⚠ 重要说明（课程要求 4）
//      本程序**只用于性能对比**，是独立的可执行文件；
//      系统本体（alice / bob / st_* 库）**不链接任何密码学库**，
//      AES 与 CMAC 全部是第一部分自己编写的实现。
//      这里链接 OpenSSL 仅仅是为了给出"库实现"这一列的数据。
//
//  对比方法（保证公平）：
//      * 同一份数据、同一把密钥、同一个 nonce，单线程、无并行优化；
//      * 两侧都按"一次性调用"的方式计时（我们的 AES::ctrXor 每次会做密钥扩展，
//        OpenSSL 每次做 EVP_EncryptInit），这正是系统实际的调用方式；
//      * 每档重复多次取平均，先做一次预热；
//      * 另外给出"密钥预扩展"的自实现数据，用于分析性能差距来自哪里。
//
//  运行：
//      ./crypto_benchmark              # 默认跑到 100 MB
//      ./crypto_benchmark --max-mb 10  # 只跑到 10 MB（快速验证）
//      OPENSSL_ia32cap=~0x200000200000000 ./crypto_benchmark   # 禁用 AES-NI，纯软件对比
// ============================================================================

#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "crypto/aes.h"
#include "crypto/cmac.h"
#include "common/hex.h"

namespace {

using Clock = std::chrono::steady_clock;

struct Measurement {
    double milliseconds = 0.0;
    double megabytesPerSecond = 0.0;
};

/// 计时辅助：多次重复后取平均。
template <typename Function>
Measurement measure(std::size_t bytes, int repeats, Function&& body) {
    // 预热一次，避免把首次的页错误/缓存冷启动计入
    body();

    const auto start = Clock::now();
    for (int i = 0; i < repeats; ++i) {
        body();
    }
    const auto end = Clock::now();

    const double totalMs =
        std::chrono::duration<double, std::milli>(end - start).count();
    Measurement result;
    result.milliseconds = totalMs / repeats;
    const double megabytes = static_cast<double>(bytes) / (1024.0 * 1024.0);
    result.megabytesPerSecond = megabytes / (result.milliseconds / 1000.0);
    return result;
}

/// 根据数据规模选择重复次数，使每档测量时间大致相当。
int repeatsFor(std::size_t bytes) {
    const double target = 32.0 * 1024 * 1024;  // 目标总处理量约 32 MB
    int repeats = static_cast<int>(target / static_cast<double>(bytes));
    if (repeats < 3) {
        repeats = 3;
    }
    if (repeats > 400) {
        repeats = 400;
    }
    return repeats;
}

std::string humanSize(std::size_t bytes) {
    std::ostringstream oss;
    if (bytes >= 1024u * 1024u) {
        oss << (bytes / (1024u * 1024u)) << " MB";
    } else {
        oss << (bytes / 1024u) << " KB";
    }
    return oss.str();
}

/// 读取 /proc/cpuinfo，判断 CPU 是否提供 AES-NI 指令集。
std::string cpuAesCapability() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.rfind("flags", 0) == 0 && line.find(" aes ") != std::string::npos) {
            return "支持 AES-NI（OpenSSL 会自动使用硬件加速）";
        }
    }
    return "不支持 AES-NI（OpenSSL 也只能用软件实现）";
}

std::string environmentNote() {
    const char* ia32cap = std::getenv("OPENSSL_ia32cap");
    if (ia32cap != nullptr) {
        return std::string("已设置 OPENSSL_ia32cap=") + ia32cap +
               "（通常用于禁用 AES-NI，得到纯软件实现的对比）";
    }
    return "未设置 OPENSSL_ia32cap（OpenSSL 使用默认能力）";
}

// ---------------------------------------------------------------------------
//  自实现（第一部分成果）
// ---------------------------------------------------------------------------

/// 一次性调用：与系统实际调用方式一致（每次做密钥扩展）
void selfAesCtrOneShot(const Key128& key, const Nonce& nonce, Bytes& buffer) {
    AES aes;
    aes.ctrXor(key, nonce, buffer.data(), buffer.size());
}

/// 单次密钥扩展的耗时（微秒）。小消息的开销主要来自这里，需要单独测量。
double measureKeyExpansionMicros(const Key128& key) {
    constexpr int kIterations = 200000;
    uint8_t roundKeys[AES128_RK_SIZE];
    aes128_key_expand(key.data(), roundKeys);  // 预热

    const auto start = Clock::now();
    for (int i = 0; i < kIterations; ++i) {
        aes128_key_expand(key.data(), roundKeys);
    }
    const auto end = Clock::now();
    return std::chrono::duration<double, std::micro>(end - start).count() / kIterations;
}

// ---------------------------------------------------------------------------
//  OpenSSL
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
//  输出
// ---------------------------------------------------------------------------

void printHeader() {
    std::cout << "# 密码算法性能对比（自实现 vs OpenSSL）" << std::endl;
    std::cout << std::endl;
    std::cout << "* OpenSSL 版本：`" << OPENSSL_VERSION_TEXT << "`" << std::endl;
    std::cout << "* CPU AES 能力：" << cpuAesCapability() << std::endl;
    std::cout << "* 运行环境：" << environmentNote() << std::endl;
    std::cout << "* 计数方式：一次性调用（含密钥扩展 / EVP 初始化），多次取平均，先预热"
              << std::endl;
    std::cout << std::endl;
}

struct Row {
    std::size_t bytes = 0;
    Measurement selfEncrypt;
    Measurement selfDecrypt;
    Measurement selfCmac;
    Measurement osslEncrypt;
    Measurement osslDecrypt;
    Measurement osslCmac;
};

void printAesTable(const std::vector<Row>& rows) {
    std::cout << "## 1. AES-128-CTR：加密 / 解密" << std::endl;
    std::cout << std::endl;
    std::cout << "| 数据大小 | 自实现加密(ms) | 库实现加密(ms) | 自实现解密(ms) | 库实现解密(ms) "
                 "| 自实现吞吐率(MB/s) | 库实现吞吐率(MB/s) | 吞吐率比(库/自) |"
              << std::endl;
    std::cout << "| --- | --- | --- | --- | --- | --- | --- | --- |" << std::endl;
    for (const Row& row : rows) {
        const double ratio = row.selfEncrypt.megabytesPerSecond > 0
                                 ? row.osslEncrypt.megabytesPerSecond /
                                       row.selfEncrypt.megabytesPerSecond
                                 : 0.0;
        std::cout << "| " << humanSize(row.bytes) << " | " << std::fixed
                  << std::setprecision(3) << row.selfEncrypt.milliseconds << " | "
                  << row.osslEncrypt.milliseconds << " | "
                  << row.selfDecrypt.milliseconds << " | "
                  << row.osslDecrypt.milliseconds << " | "
                  << std::setprecision(1) << row.selfEncrypt.megabytesPerSecond << " | "
                  << row.osslEncrypt.megabytesPerSecond << " | " << std::setprecision(2)
                  << ratio << "x |" << std::endl;
    }
    std::cout << std::endl;

}

void printCmacTable(const std::vector<Row>& rows) {
    std::cout << "## 2. CMAC（完整性标签）" << std::endl;
    std::cout << std::endl;
    std::cout << "| 数据大小 | 自实现(ms) | 库实现(ms) | 自实现吞吐率(MB/s) | 库实现吞吐率(MB/s) "
                 "| 吞吐率比(库/自) |"
              << std::endl;
    std::cout << "| --- | --- | --- | --- | --- | --- |" << std::endl;
    for (const Row& row : rows) {
        const double ratio = row.selfCmac.megabytesPerSecond > 0
                                 ? row.osslCmac.megabytesPerSecond /
                                       row.selfCmac.megabytesPerSecond
                                 : 0.0;
        std::cout << "| " << humanSize(row.bytes) << " | " << std::fixed
                  << std::setprecision(3) << row.selfCmac.milliseconds << " | "
                  << row.osslCmac.milliseconds << " | " << std::setprecision(1)
                  << row.selfCmac.megabytesPerSecond << " | "
                  << row.osslCmac.megabytesPerSecond << " | " << std::setprecision(2)
                  << ratio << "x |" << std::endl;
    }
    std::cout << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
    std::size_t maxMegabytes = 100;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--max-mb" && i + 1 < argc) {
            maxMegabytes = static_cast<std::size_t>(std::atoi(argv[++i]));
        }
    }

    const Key128 key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const Nonce nonce = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    const std::size_t sizes[] = {1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024,
                                 100 * 1024 * 1024};

    printHeader();

    std::vector<Row> rows;
    for (std::size_t size : sizes) {
        if (size > maxMegabytes * 1024 * 1024 && !rows.empty()) {
            break;
        }
        const int repeats = repeatsFor(size);

        Row row;
        row.bytes = size;
        const Bytes plaintext(size, 0xA5);

        // ---- 自实现：AES-CTR ----
        Bytes selfBuffer = plaintext;
        row.selfEncrypt = measure(size, repeats, [&]() {
            selfBuffer = plaintext;
            selfAesCtrOneShot(key, nonce, selfBuffer);
        });
        Bytes selfCipher = selfBuffer;
        row.selfDecrypt = measure(size, repeats, [&]() {
            Bytes buffer = selfCipher;
            selfAesCtrOneShot(key, nonce, buffer);
        });

        // ---- 自实现：CMAC ----
        {
            CMAC cmac;
            row.selfCmac = measure(size, repeats, [&]() {
                (void)cmac.generate(key, plaintext);
            });
        }

        // ---- OpenSSL：AES-CTR ----
        row.osslEncrypt = measure(size, repeats, [&]() {
            Bytes buffer = plaintext;
            opensslAesCtr(key, nonce, buffer, true);
        });
        {
            Bytes buffer = plaintext;
            opensslAesCtr(key, nonce, buffer, true);
            const Bytes cipher = buffer;
            row.osslDecrypt = measure(size, repeats, [&]() {
                Bytes inner = cipher;
                opensslAesCtr(key, nonce, inner, false);
            });
        }

        // ---- OpenSSL：CMAC ----
        row.osslCmac = measure(size, repeats, [&]() {
            (void)opensslCmac(key, plaintext);
        });

        rows.push_back(row);
        std::cerr << "[benchmark] " << humanSize(size) << " 完成（重复 " << repeats
                  << " 次）" << std::endl;
    }

    std::cout << std::endl;
    printAesTable(rows);
    printCmacTable(rows);

    // ---- 密钥扩展的固定开销（说明小消息为什么"吞吐率看起来低"）----
    const double keyExpansionUs = measureKeyExpansionMicros(key);
    std::cout << "## 2.1 自实现的固定开销：密钥扩展" << std::endl;
    std::cout << std::endl;
    std::cout << "我们的 `AES::ctrXor` 每次调用都会执行一次密钥扩展（与系统实际调用方式一致）；"
              << std::endl;
    std::cout << "OpenSSL 的 `EVP_EncryptInit` 同样有初始化成本。实测单次密钥扩展耗时："
              << std::endl;
    std::cout << std::endl;
    std::cout << "| 项目 | 数值 |" << std::endl;
    std::cout << "| --- | --- |" << std::endl;
    std::cout << "| 单次密钥扩展 | " << std::fixed << std::setprecision(3) << keyExpansionUs
              << " µs |" << std::endl;
    for (const Row& row : rows) {
        const double callMicros = row.selfEncrypt.milliseconds * 1000.0;
        const double share = callMicros > 0 ? keyExpansionUs / callMicros * 100.0 : 0.0;
        std::cout << "| 占 " << humanSize(row.bytes) << " 加密耗时比例 | "
                  << std::setprecision(1) << share << "% |" << std::endl;
    }
    std::cout << std::endl;

    std::cout << "## 3. 正确性交叉验证" << std::endl;
    std::cout << std::endl;
    std::cout << "对比之前先确认两侧算出的结果完全一致，避免出现「快的实现其实算错了」："
              << std::endl;
    std::cout << std::endl;
    {
        // RFC 4493 使用的测试密钥与消息
        const Bytes message = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                               0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
        const Key128 rfcKey = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

        // AES-CTR：自实现与 OpenSSL 逐字节比较
        Bytes selfCipher = message;
        AES aes;
        aes.ctrXor(rfcKey, nonce, selfCipher.data(), selfCipher.size());
        Bytes osslCipher = message;
        opensslAesCtr(rfcKey, nonce, osslCipher, true);

        std::cout << "* AES-128-CTR 密文：" << std::endl;
        std::cout << "  * 自实现：" << toHex(selfCipher) << std::endl;
        std::cout << "  * OpenSSL：" << toHex(osslCipher) << std::endl;
        std::cout << "  * 结论：" << (selfCipher == osslCipher ? "一致 ✅" : "不一致 ❌")
                  << std::endl;

        CMAC cmac;
        const MacTag selfTag = cmac.generate(rfcKey, message);
        const MacTag osslTag = opensslCmac(rfcKey, message);
        std::cout << "* CMAC：" << std::endl;
        std::cout << "  * 自实现：" << toHex(selfTag) << std::endl;
        std::cout << "  * OpenSSL：" << toHex(osslTag) << std::endl;
        std::cout << "  * 结论：" << (selfTag == osslTag ? "一致 ✅" : "不一致 ❌")
                  << std::endl;
    }
    return 0;
}
