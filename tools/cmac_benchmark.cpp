// ============================================================================
//  SecureTransfer - CMAC 性能测试（第一部分成果，加工程序）
//  file: tools/cmac_benchmark.cpp
//
//  来源：第一部分交付的 SecureTransfer 工程（原为 Windows 下的
//        cmac_benchmark.cpp，导入时去掉了 system("pause") 并补了单位换算）。
//
//  用途：课程要求 5「与库实现做性能对比」的自实现侧数据。
//        若要与 OpenSSL 对比，可先用本工具测出自实现的耗时，
//        再用 openssl dgst -mac cmac -macopt cipher:aes-128-cbc 测库实现：
//        具体命令见 docs/development.md §8。
//
//  运行：./cmac_benchmark [重复次数]
// ============================================================================

#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>

#include "crypto/cmac.h"

int main(int argc, char** argv) {
    int rounds = 10;
    if (argc > 1) {
        rounds = std::atoi(argv[1]);
        if (rounds <= 0) {
            rounds = 10;
        }
    }

    const Key128 key = {};  // 全零密钥，只用于测速
    CMAC cmac;

    std::cout << "CMAC(AES-128) 自实现性能测试，每档重复 " << rounds << " 次取平均" << std::endl;
    std::cout << "----------------------------------------------------------" << std::endl;
    std::cout << "      数据大小      平均耗时(ms)      吞吐率(MB/s)" << std::endl;

    for (size_t size : {size_t(1024), size_t(64) * 1024, size_t(1024) * 1024,
                        size_t(10) * 1024 * 1024}) {
        const Bytes message(size, 0xAB);
        const auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < rounds; ++i) {
            (void)cmac.generate(key, message);
        }
        const auto end = std::chrono::high_resolution_clock::now();

        const double ms =
            std::chrono::duration<double, std::milli>(end - start).count() / rounds;
        const double mbps = (static_cast<double>(size) / (1024.0 * 1024.0)) / (ms / 1000.0);

        std::cout << std::setw(12) << size << std::setw(16) << std::fixed
                  << std::setprecision(3) << ms << std::setw(16) << std::setprecision(2)
                  << mbps << std::endl;
    }
    return 0;
}
