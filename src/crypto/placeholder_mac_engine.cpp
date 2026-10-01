// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: src/crypto/placeholder_mac_engine.cpp
// ============================================================================

#include "crypto/placeholder_mac_engine.h"

#include "common/constant_time.h"
#include "common/hex.h"
#include "common/log.h"

namespace {

const char* const kLogModule = "Crypto";

/// FNV-1a 64 位混合。
void mixBytes(std::uint64_t& state, const Byte* data, std::size_t length) {
    constexpr std::uint64_t kPrime = 1099511628211ULL;
    for (std::size_t i = 0; i < length; ++i) {
        state ^= static_cast<std::uint64_t>(data[i]);
        state *= kPrime;
    }
}

/// splitmix64：把一个 64 位状态扩散成另一个 64 位值。
std::uint64_t splitmix64(std::uint64_t& state) {
    state += 0x9E3779B97F4A7C15ULL;
    std::uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

}  // namespace

const char* PlaceholderMacEngine::name() const {
    return "PlaceholderMacEngine(dev-only, NOT CMAC)";
}

bool PlaceholderMacEngine::isCryptographicallySecure() const {
    return false;
}

MacTag PlaceholderMacEngine::compute(const Key128& key, const Bytes& data) {
    std::uint64_t state = 1469598103934665603ULL;  // FNV offset basis
    mixBytes(state, key.data(), key.size());
    const std::uint64_t length = static_cast<std::uint64_t>(data.size());
    Byte lengthBytes[8];
    for (int i = 0; i < 8; ++i) {
        lengthBytes[i] = static_cast<Byte>((length >> (8 * (7 - i))) & 0xFF);
    }
    mixBytes(state, lengthBytes, sizeof(lengthBytes));
    mixBytes(state, data.data(), data.size());

    MacTag tag{};
    for (std::size_t i = 0; i < tag.size(); i += 8) {
        const std::uint64_t word = splitmix64(state);
        for (std::size_t j = 0; j < 8; ++j) {
            tag[i + j] = static_cast<Byte>((word >> (8 * (7 - j))) & 0xFF);
        }
    }
    return tag;
}

bool PlaceholderMacEngine::verify(const Key128& key, const Bytes& data,
                                  const MacTag& tag) {
    const MacTag expected = compute(key, data);
    return constantTimeEquals(expected, tag);
}
