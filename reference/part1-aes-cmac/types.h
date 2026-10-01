#pragma once
#include <array>
#include <vector>
#include <cstdint>

using Bytes = std::vector<uint8_t>;
using Key128 = std::array<uint8_t, 16>;
using Block128 = std::array<uint8_t, 16>;
using MacTag = std::array<uint8_t, 16>;