#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace vaultcore {

using Digest = std::array<std::uint8_t, 32>;

// Streaming SHA-256 (FIPS 180-4); no external runtime dependencies.
class Sha256 {
public:
    Sha256();
    void update(std::span<const std::uint8_t> bytes);
    Digest finish();

private:
    void transform(const std::uint8_t* block);
    std::array<std::uint32_t, 8> state_;
    std::array<std::uint8_t, 64> buffer_{};
    std::uint64_t total_bytes_ = 0;
    std::size_t buffered_ = 0;
    bool finished_ = false;
};

Digest sha256(std::span<const std::uint8_t> bytes);
Digest sha256(std::string_view text);
std::string to_hex(const Digest& digest);
Digest from_hex(std::string_view text);

} // namespace vaultcore
