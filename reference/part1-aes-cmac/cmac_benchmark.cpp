#include "cmac.h"
#include <chrono>
#include <iostream>

int main() {
	Key128 key = {};
	CMAC cmac;
	for (size_t sz : {1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024}) {
		Bytes msg(sz, 0xAB);
		auto t0 = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < 10; ++i) cmac.generate(key, msg);
		auto t1 = std::chrono::high_resolution_clock::now();
		double ms = std::chrono::duration<double, std::milli>(t1 - t0).count() / 10.0;
		double mbps = (sz / (1048576.0)) / (ms / 1000.0);
		std::cout << sz << " bytes: " << ms << " ms, " << mbps << " MB/s\n";
	}
	system("pause");
	return 0;
}