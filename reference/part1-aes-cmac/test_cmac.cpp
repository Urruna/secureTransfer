#include "cmac.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <algorithm>

static std::string toHex(const uint8_t* d, size_t n) {
	std::stringstream ss;
	for (size_t i = 0; i < n; ++i)
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)d[i];
	return ss.str();
}

static Bytes fromHex(const std::string& h) {
	Bytes out;
	for (size_t i = 0; i < h.size(); i += 2)
		out.push_back((uint8_t)std::stoi(h.substr(i, 2), nullptr, 16));
	return out;
}

int main() {
	Key128 key;
	Bytes kb = fromHex("2b7e151628aed2a6abf7158809cf4f3c");
	std::copy(kb.begin(), kb.end(), key.begin());

	struct TC { const char* name; const char* msg; const char* exp; };
	TC cases[] = {
		{"empty",   "", "bb1d6929e95937287fa37d129b756746"},
		{"16B", "6bc1bee22e409f96e93d7e117393172a",
				"070a16b46b4d4144f79bdd9dd04a287c"},
		{"40B",
		 "6bc1bee22e409f96e93d7e117393172a"
		 "ae2d8a571e03ac9c9eb76fac45af8e51"
		 "30c81c46a35ce411",
				"dfa66747de9ae63030ca32611497c827"},
		{"64B",
		 "6bc1bee22e409f96e93d7e117393172a"
		 "ae2d8a571e03ac9c9eb76fac45af8e51"
		 "30c81c46a35ce411e5fbc1191a0a52ef"
		 "f69f2445df4f9b17ad2b417be66c3710",
				"51f0bebf7e3b9d92fc49741779363cfe"},
	};

	CMAC cmac;
	int pass = 0, total = sizeof(cases) / sizeof(cases[0]);
	for (auto& tc : cases) {
		Bytes msg = fromHex(tc.msg);
		MacTag tag = cmac.generate(key, msg);
		std::string got = toHex(tag.data(), 16);
		bool ok = (got == tc.exp);
		pass += ok;
		std::cout << "[" << (ok ? "PASS" : "FAIL") << "] "
			<< tc.name << "\n  got=" << got
			<< "\n  exp=" << tc.exp << "\n";
	}
	std::cout << pass << "/" << total << " passed\n";
	system("pause"); // 防止控制台一闪而过
	return pass == total ? 0 : 1;
}