/**
 * @file Sha2.cpp
 *
 * This module contains the implementation of the
 * Hash::Sha2 function.
 *
 * © 2018 by Richard Walters
 */

#include <Hash/Sha2.hpp>
#include <string.h>
#include <stdint.h>
#include <vector>

namespace {

    /**
     * This function rotates the given argument right by the given number
     * of bits.
     *
     * @param[in] arg
     *     This is the argument to rotate.
     *
     * @param[in] bits
     *     This is the number of bits to rotate the argument.
     *
     * @return
     *     The rotated argument is returned.
     */
    uint32_t Rot(uint32_t arg, size_t bits) {
        return (
            (arg >> bits)
            | (arg << (32 - bits))
        );
    }

    /**
     * This function computes either the SHA-224 or the SHA-256 message digest
     * of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @param[in] truncate
     *     If true, compute the SHA-224 message digest.  Otherwise, compute
     *     the SHA-256 message digest.
     *
     * @return
     *     The SHA-224 or SHA-256 message digest of the given data is returned
     *     as a vector of bytes.
     */
    std::vector< uint8_t > Sha224or256(
        const std::vector< uint8_t >& data,
        bool truncate
    ) {
        // This a straightforward implementation of the pseudocode
        // found in the Wikipedia page for SHA-2
        // (https://en.wikipedia.org/wiki/SHA-2).
        uint8_t chunk[64];
        uint32_t w[64];
        uint32_t h0 = truncate ? 0xc1059ed8 : 0x6a09e667;
        uint32_t h1 = truncate ? 0x367cd507 : 0xbb67ae85;
        uint32_t h2 = truncate ? 0x3070dd17 : 0x3c6ef372;
        uint32_t h3 = truncate ? 0xf70e5939 : 0xa54ff53a;
        uint32_t h4 = truncate ? 0xffc00b31 : 0x510e527f;
        uint32_t h5 = truncate ? 0x68581511 : 0x9b05688c;
        uint32_t h6 = truncate ? 0x64f98fa7 : 0x1f83d9ab;
        uint32_t h7 = truncate ? 0xbefa4fa4 : 0x5be0cd19;
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        uint64_t ml = (uint64_t)data.size() * 8;
        for (size_t offset = 0; offset < data.size() + 9; offset += 64) {
            if (offset + 64 <= data.size()) {
                (void)memcpy(chunk, &data[offset], 64);
            } else {
                (void)memset(chunk, 0, 64);
                if (offset < data.size()) {
                    (void)memcpy(chunk, &data[offset], data.size() - offset);
                }
                if (offset <= data.size()) {
                    chunk[data.size() - offset] = 0x80;
                }
                if (offset + 64 - data.size() >= 9) {
                    chunk[56] = (uint8_t)(ml >> 56);
                    chunk[57] = (uint8_t)(ml >> 48);
                    chunk[58] = (uint8_t)(ml >> 40);
                    chunk[59] = (uint8_t)(ml >> 32);
                    chunk[60] = (uint8_t)(ml >> 24);
                    chunk[61] = (uint8_t)(ml >> 16);
                    chunk[62] = (uint8_t)(ml >> 8);
                    chunk[63] = (uint8_t)ml;
                }
            }
            for (size_t i = 0; i < 16; ++i) {
                w[i] = (
                    ((uint32_t)chunk[i * 4 + 0] << 24)
                    | ((uint32_t)chunk[i * 4 + 1] << 16)
                    | ((uint32_t)chunk[i * 4 + 2] << 8)
                    | (uint32_t)chunk[i * 4 + 3]
                );
            }
            for (size_t i = 16; i < 64; ++i) {
                w[i] = (
                    w[i - 16]
                    + (
                        Rot(w[i - 15], 7) ^ Rot(w[i - 15], 18) ^ (w[i - 15] >> 3)
                    ) // s0
                    + w[i - 7]
                    + (
                        Rot(w[i - 2], 17) ^ Rot(w[i - 2], 19) ^ (w[i - 2] >> 10)
                    ) // s1
                );
            }
            uint32_t a = h0;
            uint32_t b = h1;
            uint32_t c = h2;
            uint32_t d = h3;
            uint32_t e = h4;
            uint32_t f = h5;
            uint32_t g = h6;
            uint32_t h = h7;
            for (size_t i = 0; i < 64; ++i) {
                const auto t1 = (
                    h + (
                        Rot(e, 6) ^ Rot(e, 11) ^ Rot(e, 25)
                    ) // S1
                    + (
                        (e & f) ^ (~e & g)
                    ) // ch
                    + k[i]
                    + w[i]
                );
                const auto t2 = (
                    (
                        Rot(a, 2) ^ Rot(a, 13) ^ Rot(a, 22)
                    ) // S0
                    + (
                        (a & b) ^ (a & c) ^ (b & c)
                    ) // maj
                );
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }
        std::vector< uint8_t > digest{
            (uint8_t)((h0 >> 24) & 0xff),
            (uint8_t)((h0 >> 16) & 0xff),
            (uint8_t)((h0 >> 8) & 0xff),
            (uint8_t)(h0 & 0xff),
            (uint8_t)((h1 >> 24) & 0xff),
            (uint8_t)((h1 >> 16) & 0xff),
            (uint8_t)((h1 >> 8) & 0xff),
            (uint8_t)(h1 & 0xff),
            (uint8_t)((h2 >> 24) & 0xff),
            (uint8_t)((h2 >> 16) & 0xff),
            (uint8_t)((h2 >> 8) & 0xff),
            (uint8_t)(h2 & 0xff),
            (uint8_t)((h3 >> 24) & 0xff),
            (uint8_t)((h3 >> 16) & 0xff),
            (uint8_t)((h3 >> 8) & 0xff),
            (uint8_t)(h3 & 0xff),
            (uint8_t)((h4 >> 24) & 0xff),
            (uint8_t)((h4 >> 16) & 0xff),
            (uint8_t)((h4 >> 8) & 0xff),
            (uint8_t)(h4 & 0xff),
            (uint8_t)((h5 >> 24) & 0xff),
            (uint8_t)((h5 >> 16) & 0xff),
            (uint8_t)((h5 >> 8) & 0xff),
            (uint8_t)(h5 & 0xff),
            (uint8_t)((h6 >> 24) & 0xff),
            (uint8_t)((h6 >> 16) & 0xff),
            (uint8_t)((h6 >> 8) & 0xff),
            (uint8_t)(h6 & 0xff)
        };
        if (!truncate) {
            digest.push_back((uint8_t)((h7 >> 24) & 0xff));
            digest.push_back((uint8_t)((h7 >> 16) & 0xff));
            digest.push_back((uint8_t)((h7 >> 8) & 0xff));
            digest.push_back((uint8_t)(h7 & 0xff));
        }
        return digest;
    }

}

namespace Hash {

    std::vector< uint8_t > Sha224(const std::vector< uint8_t >& data) {
        return Sha224or256(data, true);
    }

    std::vector< uint8_t > Sha256(const std::vector< uint8_t >& data) {
        return Sha224or256(data, false);
    }

}
