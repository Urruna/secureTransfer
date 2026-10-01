// ============================================================================
//  SecureTransfer - 第一部分成果：CMAC（RFC 4493）实现
//  file: src/crypto/cmac.cpp
//
//  来源：第一部分交付的 Windows/Visual Studio 工程 SecureTransfer
//        （原件存档于 reference/part1-aes-cmac/cmac.cpp）。
//        导入时只调整了编码（GBK → UTF-8）与 include 路径，算法未改动。
//
//  实现要点：K1 / K2 子密钥由 L = AES(K, 0^128) 左移并在最高位为 1 时
//  异或 Rb = 0x00..87 得到；最后一块完整时异或 K1，不完整时先填充 0x80..00
//  再异或 K2。已用 RFC 4493 的 4 条标准向量验证。
// ============================================================================

#include "crypto/cmac.h"

#include <algorithm>

#include "crypto/aes.h"

namespace {
	const Block128 Rb = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x87 };
}

Block128 CMAC::xorBlock(const Block128& a, const Block128& b) {
	Block128 out;
	for (int i = 0; i < 16; ++i) out[i] = a[i] ^ b[i];
	return out;
}

Block128 CMAC::leftShift(const Block128& in) {
	Block128 out;
	uint8_t carry = 0;
	for (int i = 15; i >= 0; --i) {
		out[i] = (uint8_t)((in[i] << 1) | carry);
		carry = (in[i] >> 7) & 1;
	}
	return out;
}

bool CMAC::msbSet(const Block128& in) {
	return (in[0] & 0x80) != 0;
}

void CMAC::deriveSubkeys(const Key128& key, Block128& K1, Block128& K2) {
	// 1. 只扩展一次密钥
	uint8_t rk[AES128_RK_SIZE];
	aes128_key_expand(key.data(), rk);

	// 2. 用底层函数加密 zero 块
	Block128 zero = {};
	uint8_t Lb[16];
	aes128_encrypt_block(rk, zero.data(), Lb);

	Block128 L;
	std::copy(Lb, Lb + 16, L.begin());

	K1 = leftShift(L);
	if (msbSet(L)) K1 = xorBlock(K1, Rb);

	K2 = leftShift(K1);
	if (msbSet(K1)) K2 = xorBlock(K2, Rb);
}

Block128 CMAC::padBlock(const uint8_t* data, size_t len) {
	Block128 out = {};
	for (size_t i = 0; i < len; ++i) out[i] = data[i];
	out[len] = 0x80;
	return out;
}

MacTag CMAC::generate(const Key128& key, const Bytes& message) {
	Block128 K1, K2;
	deriveSubkeys(key, K1, K2);

	// 1. 在这里扩展一次密钥，后面循环里反复用
	uint8_t rk[AES128_RK_SIZE];
	aes128_key_expand(key.data(), rk);

	const size_t len = message.size();
	size_t n = (len + 15) / 16;
	if (n == 0) n = 1;

	const bool lastComplete = (len > 0 && len % 16 == 0);

	Block128 X = {};

	for (size_t i = 0; i + 1 < n; ++i) {
		Block128 M;
		std::copy(message.begin() + i * 16,
			message.begin() + (i + 1) * 16,
			M.begin());
		X = xorBlock(X, M);

		// 2. 直接调用底层函数，不再重新扩展密钥
		uint8_t Xb[16];
		aes128_encrypt_block(rk, X.data(), Xb);
		std::copy(Xb, Xb + 16, X.begin());
	}

	Block128 lastBlock;
	if (lastComplete) {
		std::copy(message.begin() + (n - 1) * 16,
			message.begin() + n * 16,
			lastBlock.begin());
		lastBlock = xorBlock(lastBlock, K1);
	}
	else {
		const size_t lastLen = len - (n - 1) * 16;
		const uint8_t* lastData =
			(len == 0) ? nullptr : message.data() + (n - 1) * 16;
		lastBlock = padBlock(lastData, lastLen);
		lastBlock = xorBlock(lastBlock, K2);
	}

	X = xorBlock(X, lastBlock);

	// 3. 最后一次加密也直接复用 rk
	uint8_t tagBytes[16];
	aes128_encrypt_block(rk, X.data(), tagBytes);

	MacTag tag;
	std::copy(tagBytes, tagBytes + 16, tag.begin());
	return tag;
}

bool CMAC::verify(const Key128& key, const Bytes& message, const MacTag& tag) {
	MacTag computed = generate(key, message);
	uint8_t diff = 0;
	for (int i = 0; i < 16; ++i) diff |= (uint8_t)(computed[i] ^ tag[i]);
	return diff == 0;
}
