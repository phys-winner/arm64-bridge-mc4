#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <errno.h>
#include <unistd.h>

// Streaming SHA-256 for external OBB provenance. No platform-private crypto
// library or 2-GB allocation is needed; the caller owns the descriptor.
namespace mc4 {

class Sha256 {
public:
    void Update(const uint8_t* input, size_t length) {
        bytes_ += length;
        while (length) {
            const size_t n = length < sizeof(block_) - used_ ? length : sizeof(block_) - used_;
            memcpy(block_ + used_, input, n);
            used_ += n;
            input += n;
            length -= n;
            if (used_ == sizeof(block_)) {
                Transform(block_);
                used_ = 0;
            }
        }
    }

    std::string Finish() {
        const uint64_t bits = bytes_ * 8u;
        const uint8_t marker = 0x80;
        Update(&marker, 1);
        const uint8_t zero = 0;
        while (used_ != 56) Update(&zero, 1);
        uint8_t length[8];
        for (int i = 0; i < 8; ++i) length[7 - i] = (uint8_t)(bits >> (i * 8));
        Update(length, sizeof(length));
        static constexpr char hex[] = "0123456789abcdef";
        std::string digest(64, '0');
        for (size_t i = 0; i < 8; ++i) {
            for (size_t j = 0; j < 4; ++j) {
                const uint8_t b = (uint8_t)(state_[i] >> (24 - 8 * j));
                digest[i * 8 + j * 2] = hex[b >> 4];
                digest[i * 8 + j * 2 + 1] = hex[b & 15];
            }
        }
        return digest;
    }

private:
    static uint32_t Ror(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

    void Transform(const uint8_t* data) {
        static constexpr uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
            0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        };
        uint32_t w[64];
        for (size_t i = 0; i < 16; ++i) {
            const size_t p = i * 4;
            w[i] = ((uint32_t)data[p] << 24) | ((uint32_t)data[p + 1] << 16) |
                   ((uint32_t)data[p + 2] << 8) | data[p + 3];
        }
        for (size_t i = 16; i < 64; ++i) {
            const uint32_t a = w[i - 15], b = w[i - 2];
            const uint32_t s0 = Ror(a, 7) ^ Ror(a, 18) ^ (a >> 3);
            const uint32_t s1 = Ror(b, 17) ^ Ror(b, 19) ^ (b >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (size_t i = 0; i < 64; ++i) {
            const uint32_t s1 = Ror(e, 6) ^ Ror(e, 11) ^ Ror(e, 25);
            const uint32_t choice = (e & f) ^ (~e & g);
            const uint32_t t1 = h + s1 + choice + k[i] + w[i];
            const uint32_t s0 = Ror(a, 2) ^ Ror(a, 13) ^ Ror(a, 22);
            const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = s0 + majority;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }

    uint32_t state_[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t block_[64] = {};
    size_t used_ = 0;
    uint64_t bytes_ = 0;
};

inline bool Sha256FileEquals(int fd, int64_t size, const char* expected, std::string* actual) {
    if (size < 0) return false;
    Sha256 sha;
    std::vector<uint8_t> buffer(1u << 20);
    int64_t position = 0;
    while (position < size) {
        const size_t count = (size - position < (int64_t)buffer.size())
                                 ? (size_t)(size - position) : buffer.size();
        const ssize_t got = pread(fd, buffer.data(), count, position);
        if (got <= 0) return false;
        sha.Update(buffer.data(), (size_t)got);
        position += got;
    }
    *actual = sha.Finish();
    return *actual == expected;
}

}  // namespace mc4
