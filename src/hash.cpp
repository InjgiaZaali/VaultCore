#include "vaultcore/hash.hpp"

#include <algorithm>
#include <stdexcept>

namespace vaultcore {
namespace {
constexpr std::array<std::uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
constexpr std::uint32_t rotate(std::uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
constexpr int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
} // namespace

Sha256::Sha256() : state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} {}

void Sha256::transform(const std::uint8_t* block) {
    std::array<std::uint32_t, 64> words{};
    for (std::size_t i = 0; i < 16; ++i) {
        const std::size_t j = i * 4;
        words[i] = (std::uint32_t(block[j]) << 24) | (std::uint32_t(block[j + 1]) << 16)
                 | (std::uint32_t(block[j + 2]) << 8) | std::uint32_t(block[j + 3]);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const auto s0 = rotate(words[i-15], 7) ^ rotate(words[i-15], 18) ^ (words[i-15] >> 3);
        const auto s1 = rotate(words[i-2], 17) ^ rotate(words[i-2], 19) ^ (words[i-2] >> 10);
        words[i] = words[i-16] + s0 + words[i-7] + s1;
    }
    auto [a,b,c,d,e,f,g,h] = state_;
    for (std::size_t i = 0; i < 64; ++i) {
        const auto s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
        const auto choose = (e & f) ^ (~e & g);
        const auto t1 = h + s1 + choose + K[i] + words[i];
        const auto s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
        const auto majority = (a & b) ^ (a & c) ^ (b & c);
        const auto t2 = s0 + majority;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    for (std::size_t i = 0; i < 8; ++i) state_[i] += std::array<std::uint32_t,8>{a,b,c,d,e,f,g,h}[i];
}

void Sha256::update(std::span<const std::uint8_t> bytes) {
    if (finished_) throw std::logic_error("SHA-256 has already been finalized");
    if (bytes.size() > (UINT64_MAX / 8) - total_bytes_) throw std::length_error("SHA-256 input too large");
    total_bytes_ += bytes.size();
    std::size_t index = 0;
    if (buffered_) {
        const auto count = std::min<std::size_t>(64 - buffered_, bytes.size());
        std::copy_n(bytes.data(), count, buffer_.data() + buffered_);
        buffered_ += count;
        index += count;
        if (buffered_ == 64) { transform(buffer_.data()); buffered_ = 0; }
        if (index == bytes.size()) return;
    }
    while (index + 64 <= bytes.size()) {
        transform(bytes.data() + index);
        index += 64;
    }
    buffered_ = bytes.size() - index;
    if (buffered_) std::copy_n(bytes.data() + index, buffered_, buffer_.data());
}

Digest Sha256::finish() {
    if (finished_) throw std::logic_error("SHA-256 has already been finalized");
    const std::uint64_t bits = total_bytes_ * 8;
    buffer_[buffered_++] = 0x80;
    if (buffered_ > 56) {
        std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_), buffer_.end(), 0);
        transform(buffer_.data());
        buffered_ = 0;
    }
    std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_), buffer_.begin() + 56, 0);
    for (std::size_t i = 0; i < 8; ++i) buffer_[56 + i] = std::uint8_t(bits >> ((7 - i) * 8));
    transform(buffer_.data());
    finished_ = true;
    Digest result{};
    for (std::size_t i = 0; i < 8; ++i) {
        for (std::size_t j = 0; j < 4; ++j) result[i * 4 + j] = std::uint8_t(state_[i] >> ((3 - j) * 8));
    }
    return result;
}

Digest sha256(std::span<const std::uint8_t> bytes) {
    Sha256 hash;
    hash.update(bytes);
    return hash.finish();
}
Digest sha256(std::string_view text) {
    return sha256({reinterpret_cast<const std::uint8_t*>(text.data()), text.size()});
}
std::string to_hex(const Digest& digest) {
    constexpr char chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (auto b : digest) { result.push_back(chars[b >> 4]); result.push_back(chars[b & 15]); }
    return result;
}
Digest from_hex(std::string_view text) {
    if (text.size() != 64) throw std::invalid_argument("Expected 64 hex digits");
    Digest result{};
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = hex_digit(text[2*i]);
        const int lo = hex_digit(text[2*i+1]);
        if (hi < 0 || lo < 0) throw std::invalid_argument("Invalid SHA-256 digest");
        result[i] = std::uint8_t((hi << 4) | lo);
    }
    return result;
}
} // namespace vaultcore
