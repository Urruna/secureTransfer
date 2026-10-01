// ============================================================================
//  SecureTransfer - 第一部分 AES 成果的回归测试
//  file: tests/unit/test_aes_core.c
//
//  来源：D:\圈圈\课程\算法设计与实验\AES\大作业\test.c
//        导入时做了三处调整（算法与测试数据均未改动）：
//          1. include 改为 "crypto/aes_core.h"；
//          2. 去掉结尾的 getchar()（否则 ctest 会一直阻塞等输入）；
//          3. 失败时返回非 0，便于 ctest 判定通过/失败。
//
//  本文件是"第一部分成果仍然有效"的回归基线，第二部分每次改动都要跑它。
// ============================================================================

#include <stdio.h>
#include <string.h>

#include "crypto/aes_core.h"

static int g_failures = 0;

static void print_hex(const char* name, const uint8_t* b, int len) {
    printf("%s", name);
    for (int i = 0; i < len; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

/* 加密->解密->比较，自动判断是否通过 */
static int roundtrip(const uint8_t rk[176], const char* label,
                     const uint8_t* data, int len) {
    uint8_t buf[512];
    uint8_t nonce[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    memcpy(buf, data, (size_t)len);

    aes_ctr_xor(rk, nonce, buf, (size_t)len); /* 加密 */
    print_hex("  密文: ", buf, len);
    aes_ctr_xor(rk, nonce, buf, (size_t)len); /* 解密 */

    const int ok = (memcmp(buf, data, (size_t)len) == 0);
    printf("[%s] %s  (长度 %d 字节)\n\n", ok ? "通过" : "失败", label, len);
    if (!ok) {
        g_failures++;
    }
    return ok;
}

int main(void) {
    /* FIPS-197 分组加密标准测试向量 */
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t rk[176], ct[16];
    aes_key_expand(key, rk);
    aes_encrypt_block(rk, pt, ct);
    print_hex("AES分组密文: ", ct, 16);
    printf("标准答案   : 69c4e0d86a7b0430d8cdb78070b4c55a\n\n");

    const uint8_t expected[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    if (memcmp(ct, expected, 16) != 0) {
        printf("[失败] AES 单块加密与 FIPS-197 标准向量不一致\n");
        g_failures++;
    } else {
        printf("[通过] AES 单块加密与 FIPS-197 标准向量一致\n\n");
    }

    /* 测试1：短文本 */
    const char* m1 = "Hello Bob!";
    roundtrip(rk, "测试1 短文本", (const uint8_t*)m1, (int)strlen(m1));

    /* 测试2：普通英文 */
    const char* m2 = "A secure message between Alice and Bob.";
    roundtrip(rk, "测试2 英文文本", (const uint8_t*)m2, (int)strlen(m2));

    /* 测试3：长文本+数字+特殊字符 */
    const char* m3 =
        "Transfer #1024: Alice->Bob, amount=500.00 USD; "
        "status=OK! (check: 9f8e7d6c)";
    roundtrip(rk, "测试3 长文本特殊字符", (const uint8_t*)m3, (int)strlen(m3));

    /* 测试4：中文（UTF-8 编码，多字节） */
    const char* m4 = "你好，Bob，这是一次安全通信测试。";
    roundtrip(rk, "测试4 中文UTF-8", (const uint8_t*)m4, (int)strlen(m4));

    /* 测试5：非16整数倍长度的二进制数据（模拟文件内容） */
    uint8_t m5[37];
    for (int i = 0; i < 37; i++) {
        m5[i] = (uint8_t)(i * 7 + 3);
    }
    roundtrip(rk, "测试5 二进制37字节(非整块)", m5, 37);

    if (g_failures != 0) {
        printf("=== AES_CORE TESTS FAILED: %d ===\n", g_failures);
        return 1;
    }
    printf("=== AES_CORE ALL TESTS PASSED ===\n");
    return 0;
}
