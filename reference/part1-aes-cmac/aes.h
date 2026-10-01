#pragma once
#include "types.h"
#include <cstddef>
#include <cstdint>

#define AES128_RK_SIZE 176

// 暴露底层 C 函数，供 CMAC 等高性能模块直接使用，避免重复扩展密钥
void aes128_key_expand(const uint8_t key[16], uint8_t rk[AES128_RK_SIZE]);
void aes128_encrypt_block(const uint8_t rk[AES128_RK_SIZE],
	const uint8_t in[16],
	uint8_t out[16]);

class AES {
public:
	// CMAC 用的单分组加密接口
	Bytes encryptBlock(const Key128& key, const Block128& block);

	// TCP 业务用 CTR 模式
	void ctrXor(const Key128& key, const Block128& nonce,
		uint8_t* data, size_t len);
};