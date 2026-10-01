#pragma once
#include "types.h"

class CMAC {
public:
	MacTag generate(const Key128& key, const Bytes& message);
	bool   verify(const Key128& key, const Bytes& message, const MacTag& tag);

private:
	static Block128 xorBlock(const Block128& a, const Block128& b);
	static Block128 leftShift(const Block128& in);
	static bool     msbSet(const Block128& in);
	static void     deriveSubkeys(const Key128& key, Block128& K1, Block128& K2);
	static Block128 padBlock(const uint8_t* data, size_t len);
};