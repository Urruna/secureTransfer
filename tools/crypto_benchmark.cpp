// ============================================================================
//  SecureTransfer - 密码算法性能对比（自实现 vs 多个库实现）
//  file: tools/crypto_benchmark.cpp
//
//  对应课程要求 5 / project_q1.md §10：
//      "将自己的密码算法实现与库文件或别人的代码实现进行全面的性能对比"
//      数据规模：1 KB / 64 KB / 1 MB / 10 MB / 100 MB
//      记录：加密时间、解密时间、吞吐率，并结合实现方式/优化/硬件加速解释差异
//
//  ⚠ 重要说明（课程要求 4）
//      本程序**只用于性能对比**，是独立的可执行文件；
//      系统本体（alice / bob / st_* 库）**不链接任何密码学库**，
//      AES 与 CMAC 全部是第一部分自己编写的实现。
//      这里链接各库仅仅是为了给出"库实现"这一列的数据。
//
//  对比方法（保证公平）：
//      * 同一份数据、同一把密钥、同一个 nonce，单线程、无并行；
//      * 所有实现都按"一次性调用"计时（含密钥扩展 / 上下文初始化）——
//        这正是本系统实际的调用方式；
//      * 每档先预热一次，再重复多次取平均（重复次数按数据规模自适应）；
//      * **先做正确性交叉验证**：各方密文与 CMAC 必须逐字节一致，否则不可比；
//      * 每个后端都会标注"是否使用硬件加速"，并另有一组"纯软件对纯软件"的数据：
//          - OpenSSL：运行时环境变量 OPENSSL_ia32cap=~0x200000200000000；
//          - Mbed TLS / Botan：硬件指令是编译期决定，故另建一份禁用 AES-NI 的库
//            （对应可执行文件 crypto_benchmark_soft）。
//
//  运行：
//      ./crypto_benchmark                      # 默认跑到 100 MB
//      ./crypto_benchmark --max-mb 10          # 只跑到 10 MB（快速验证）
//      ./crypto_benchmark --csv hw.csv --label hw
//      OPENSSL_ia32cap=~0x200000200000000 ./crypto_benchmark    # OpenSSL 纯软件
//      ./crypto_benchmark_soft --csv sw.csv --label sw          # 全纯软件对照
// ============================================================================

#include "bench_backend.h"

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

#include "common/hex.h"
#include "crypto/aes.h"
#include "crypto/cmac.h"

namespace {

using Clock = std::chrono::steady_clock;

struct Measurement {
    double milliseconds = 0.0;
    double megabytesPerSecond = 0.0;
};

/// 计时辅助：多次重复后取平均（先预热一次，去掉首次的页错误/缓存冷启动）。
template <typename Function>
Measurement measure(std::size_t bytes, int repeats, Function&& body) {
    body();

    const auto start = Clock::now();
    for (int i = 0; i < repeats; ++i) {
        body();
    }
    const auto end = Clock::now();

    const double totalMs = std::chrono::duration<double, std::milli>(end - start).count();
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

/// 判断 CPU 是否提供 AES-NI 指令集。
/// Linux ：读 /proc/cpuinfo 的 flags 行；
/// Windows：没有 /proc/cpuinfo，改用编译器内建能力检测（MinGW/GCC、Clang 均支持）。
std::string cpuAesCapability() {
#if defined(_WIN32)
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    if (__builtin_cpu_supports("aes") != 0) {
        return "支持 AES-NI（支持硬件加速的库会自动使用）";
    }
    return "不支持 AES-NI（所有实现都只能用软件路径）";
#else
    return "未知（当前编译器不支持 CPU 能力检测）";
#endif
#else
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.rfind("flags", 0) == 0 && line.find(" aes ") != std::string::npos) {
            return "支持 AES-NI（支持硬件加速的库会自动使用）";
        }
    }
    return "不支持 AES-NI（所有实现都只能用软件路径）";
#endif
}

std::string environmentNote() {
    const char* ia32cap = std::getenv("OPENSSL_ia32cap");
    if (ia32cap != nullptr) {
        return std::string("已设置 OPENSSL_ia32cap=") + ia32cap +
               "（OpenSSL 走纯软件路径；其它库不受该变量影响）";
    }
    return "未设置 OPENSSL_ia32cap（OpenSSL 使用默认能力）";
}

/// 汇总所有编译进来的后端：第一个固定是"自实现"。
std::vector<const bench::Backend*> collectBackends() {
    std::vector<const bench::Backend*> backends;
    backends.push_back(&bench::selfBackend());
#if defined(ST_BENCH_WITH_OPENSSL)
    backends.push_back(&bench::opensslBackend());
#endif
#if defined(ST_BENCH_WITH_MBEDTLS)
    backends.push_back(&bench::mbedtlsBackend());
#endif
#if defined(ST_BENCH_WITH_BOTAN)
    backends.push_back(&bench::botanBackend());
#endif
    return backends;
}

struct Row {
    std::size_t bytes = 0;
    std::vector<Measurement> aesEncrypt;  // 按后端索引
    std::vector<Measurement> aesDecrypt;
    std::vector<Measurement> cmac;
};

void printHeader(const std::vector<const bench::Backend*>& backends) {
    std::cout << "# 密码算法性能对比（自实现 vs 库实现）" << std::endl;
    std::cout << std::endl;
    std::cout << "* CPU AES 能力：`" << cpuAesCapability() << "`" << std::endl;
    std::cout << "* 运行环境：`" << environmentNote() << "`" << std::endl;
    std::cout << "* 计数方式：一次性调用（含密钥扩展 / 上下文初始化），先预热，多次取平均"
              << std::endl;
    std::cout << "* 参与对比的实现：" << std::endl;
    for (const bench::Backend* backend : backends) {
        std::cout << "  * **" << backend->name << "** —— " << backend->accel;
        if (!backend->note.empty()) {
            std::cout << "（" << backend->note << "）";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
}

void printAesTable(const std::vector<Row>& rows, const std::vector<const bench::Backend*>& backends) {
    std::cout << "## 1. AES-128-CTR：加密 / 解密" << std::endl;
    std::cout << std::endl;

    for (std::size_t b = 0; b < backends.size(); ++b) {
        std::cout << "### " << backends[b]->name << "（" << backends[b]->accel << "）" << std::endl;
        std::cout << std::endl;
        std::cout << "| 数据大小 | 自实现加密(ms) | 本实现加密(ms) | 自实现解密(ms) | 本实现解密(ms) "
                     "| 自实现吞吐率(MB/s) | 本实现吞吐率(MB/s) | 吞吐率比(本/自) |"
                  << std::endl;
        std::cout << "| --- | --- | --- | --- | --- | --- | --- | --- |" << std::endl;
        for (const Row& row : rows) {
            const double selfMb = row.aesEncrypt[0].megabytesPerSecond;
            const double otherMb = row.aesEncrypt[b].megabytesPerSecond;
            const double ratio = selfMb > 0 ? otherMb / selfMb : 0.0;
            std::cout << "| " << humanSize(row.bytes) << " | " << std::fixed << std::setprecision(3)
                      << row.aesEncrypt[0].milliseconds << " | " << row.aesEncrypt[b].milliseconds
                      << " | " << row.aesDecrypt[0].milliseconds << " | "
                      << row.aesDecrypt[b].milliseconds << " | " << std::setprecision(1) << selfMb
                      << " | " << otherMb << " | " << std::setprecision(2) << ratio << "x |"
                      << std::endl;
        }
        std::cout << std::endl;
    }
}

void printCmacTable(const std::vector<Row>& rows, const std::vector<const bench::Backend*>& backends) {
    std::cout << "## 2. CMAC（完整性标签）" << std::endl;
    std::cout << std::endl;

    for (std::size_t b = 0; b < backends.size(); ++b) {
        std::cout << "### " << backends[b]->name << "（" << backends[b]->accel << "）" << std::endl;
        std::cout << std::endl;
        std::cout << "| 数据大小 | 自实现(ms) | 本实现(ms) | 自实现吞吐率(MB/s) | 本实现吞吐率(MB/s) "
                     "| 吞吐率比(本/自) |"
                  << std::endl;
        std::cout << "| --- | --- | --- | --- | --- | --- |" << std::endl;
        for (const Row& row : rows) {
            const double selfMb = row.cmac[0].megabytesPerSecond;
            const double otherMb = row.cmac[b].megabytesPerSecond;
            const double ratio = selfMb > 0 ? otherMb / selfMb : 0.0;
            std::cout << "| " << humanSize(row.bytes) << " | " << std::fixed << std::setprecision(3)
                      << row.cmac[0].milliseconds << " | " << row.cmac[b].milliseconds << " | "
                      << std::setprecision(1) << selfMb << " | " << otherMb << " | "
                      << std::setprecision(2) << ratio << "x |" << std::endl;
        }
        std::cout << std::endl;
    }
}

/// 汇总表：把"相对自实现的吞吐率倍率"横向排开，方便一眼看差距。
void printSummaryTable(const std::vector<Row>& rows,
                       const std::vector<const bench::Backend*>& backends) {
    std::cout << "## 3. 汇总表：相对自实现的吞吐率倍率" << std::endl;
    std::cout << std::endl;

    std::cout << "| 数据大小 | 运算 |";
    for (const bench::Backend* backend : backends) {
        std::cout << " " << backend->id << " |";
    }
    std::cout << std::endl;
    std::cout << "| --- | --- |";
    for (std::size_t b = 0; b < backends.size(); ++b) {
        std::cout << " --- |";
    }
    std::cout << std::endl;

    for (const Row& row : rows) {
        const double selfEnc = row.aesEncrypt[0].megabytesPerSecond;
        const double selfMac = row.cmac[0].megabytesPerSecond;
        std::cout << "| " << humanSize(row.bytes) << " | AES-CTR |";
        for (std::size_t b = 0; b < backends.size(); ++b) {
            const double ratio = selfEnc > 0 ? row.aesEncrypt[b].megabytesPerSecond / selfEnc : 0.0;
            std::cout << " " << std::fixed << std::setprecision(2) << ratio << "x |";
        }
        std::cout << std::endl;
        std::cout << "| " << humanSize(row.bytes) << " | CMAC |";
        for (std::size_t b = 0; b < backends.size(); ++b) {
            const double ratio = selfMac > 0 ? row.cmac[b].megabytesPerSecond / selfMac : 0.0;
            std::cout << " " << std::fixed << std::setprecision(2) << ratio << "x |";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
    std::cout << "（表中数字为 `本实现吞吐率 ÷ 自实现吞吐率`；`" << backends[0]->id
              << "` 恒为 1.00x）" << std::endl;
    std::cout << std::endl;
}

/// 正确性交叉验证：各方密文与 CMAC 必须与自实现逐字节一致，性能数字才有意义。
bool printCorrectnessCheck(const std::vector<const bench::Backend*>& backends) {
    std::cout << "## 4. 正确性交叉验证（比性能之前先做）" << std::endl;
    std::cout << std::endl;

    const Key128 key = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    const Nonce nonce = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const Bytes plaintext = stringToBytes(
        "SecureTransfer benchmark: the quick brown fox jumps over the lazy dog. 0123456789");

    Bytes referenceCipher = plaintext;
    backends[0]->aesCtr(key, nonce, referenceCipher, true);
    const MacTag referenceTag = backends[0]->cmac(key, plaintext);

    std::cout << "AES-128-CTR 密文（前 16 字节）与 CMAC 的对照：" << std::endl;
    std::cout << std::endl;
    std::cout << "| 实现 | AES-CTR 密文(前 16 字节) | 一致 | CMAC | 一致 |" << std::endl;
    std::cout << "| --- | --- | --- | --- | --- |" << std::endl;

    bool allMatch = true;
    for (const bench::Backend* backend : backends) {
        Bytes cipher = plaintext;
        backend->aesCtr(key, nonce, cipher, true);
        const MacTag tag = backend->cmac(key, plaintext);
        const bool cipherOk = cipher == referenceCipher;
        const bool tagOk = tag == referenceTag;
        allMatch = allMatch && cipherOk && tagOk;
        std::cout << "| " << backend->name << " | "
                  << toHex(referenceCipher.data(), std::min<std::size_t>(16, cipher.size())) << "… | "
                  << (cipherOk ? "✅" : "❌") << " | " << toHex(tag) << " | "
                  << (tagOk ? "✅" : "❌") << " |" << std::endl;
    }
    std::cout << std::endl;
    std::cout << (allMatch ? "**结论：所有实现结果逐字节一致，性能数字可比。**"
                           : "**结论：存在不一致的实现，其性能数字不可比！**")
              << std::endl;
    std::cout << std::endl;
    return allMatch;
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

void printKeyExpansionSection(const Key128& key, const std::vector<Row>& rows) {
    const double micros = measureKeyExpansionMicros(key);
    std::cout << "## 5. 自实现的固定开销：密钥扩展" << std::endl;
    std::cout << std::endl;
    std::cout << "| 项目 | 数值 |" << std::endl;
    std::cout << "| --- | --- |" << std::endl;
    std::cout << "| 单次密钥扩展 | " << std::fixed << std::setprecision(3) << micros << " µs |"
              << std::endl;
    for (const Row& row : rows) {
        const double percent = row.aesEncrypt[0].milliseconds > 0
                                   ? (micros / 1000.0) / row.aesEncrypt[0].milliseconds * 100.0
                                   : 0.0;
        std::cout << "| 占 " << humanSize(row.bytes) << " 自实现加密耗时比例 | " << std::setprecision(1)
                  << percent << "% |" << std::endl;
    }
    std::cout << std::endl;
}

void writeCsv(const std::string& path, const std::string& label, const std::vector<Row>& rows,
              const std::vector<const bench::Backend*>& backends) {
    std::ofstream out(path);
    if (!out) {
        std::cerr << "[WARN] 无法写入 CSV: " << path << std::endl;
        return;
    }
    out << "label,backend,size_bytes,operation,milliseconds,mb_per_s\n";
    out << std::fixed << std::setprecision(6);
    for (const Row& row : rows) {
        for (std::size_t b = 0; b < backends.size(); ++b) {
            out << label << "," << backends[b]->id << "," << row.bytes << ",aes_encrypt,"
                << row.aesEncrypt[b].milliseconds << "," << row.aesEncrypt[b].megabytesPerSecond
                << "\n";
            out << label << "," << backends[b]->id << "," << row.bytes << ",aes_decrypt,"
                << row.aesDecrypt[b].milliseconds << "," << row.aesDecrypt[b].megabytesPerSecond
                << "\n";
            out << label << "," << backends[b]->id << "," << row.bytes << ",cmac,"
                << row.cmac[b].milliseconds << "," << row.cmac[b].megabytesPerSecond << "\n";
        }
    }
    std::cout << "（已写出 CSV：`" << path << "`，标签 `" << label << "`）" << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
    std::size_t maxMegabytes = 100;
    std::string csvPath;
    std::string label = "run";
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--max-mb" && i + 1 < argc) {
            maxMegabytes = static_cast<std::size_t>(std::atoi(argv[++i]));
        } else if (arg == "--csv" && i + 1 < argc) {
            csvPath = argv[++i];
        } else if (arg == "--label" && i + 1 < argc) {
            label = argv[++i];
        }
    }

    const Key128 key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const Nonce nonce = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const std::size_t sizes[] = {1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024,
                                 100 * 1024 * 1024};

    const std::vector<const bench::Backend*> backends = collectBackends();
    printHeader(backends);

    std::vector<Row> rows;
    for (std::size_t size : sizes) {
        if (size > maxMegabytes * 1024 * 1024 && !rows.empty()) {
            break;
        }
        const int repeats = repeatsFor(size);

        Row row;
        row.bytes = size;
        row.aesEncrypt.assign(backends.size(), Measurement{});
        row.aesDecrypt.assign(backends.size(), Measurement{});
        row.cmac.assign(backends.size(), Measurement{});
        const Bytes plaintext(size, 0xA5);

        std::cout << "[benchmark] " << humanSize(size) << " 完成（重复 " << repeats << " 次）"
                  << std::endl;

        for (std::size_t b = 0; b < backends.size(); ++b) {
            Bytes buffer = plaintext;
            row.aesEncrypt[b] = measure(size, repeats, [&]() {
                buffer = plaintext;
                backends[b]->aesCtr(key, nonce, buffer, true);
            });
            row.aesDecrypt[b] = measure(size, repeats, [&]() {
                buffer = plaintext;
                backends[b]->aesCtr(key, nonce, buffer, false);
            });
            row.cmac[b] = measure(size, repeats, [&]() {
                const MacTag tag = backends[b]->cmac(key, plaintext);
                if (tag.empty()) {
                    std::abort();  // 不可达，仅用于防止优化掉调用
                }
            });
        }
        rows.push_back(row);
    }
    std::cout << std::endl;

    const bool consistent = printCorrectnessCheck(backends);
    printAesTable(rows, backends);
    printCmacTable(rows, backends);
    printSummaryTable(rows, backends);
    printKeyExpansionSection(key, rows);

    if (!csvPath.empty()) {
        writeCsv(csvPath, label, rows, backends);
    }
    return consistent ? 0 : 1;
}
