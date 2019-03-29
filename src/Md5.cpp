/**
 * @file Md5.cpp
 *
 * This module contains the implementation of the
 * Hash::Md5 function.
 *
 * © 2019 by Richard Walters
 */

#include <Hash/Md5.hpp>
#include <string.h>
#include <stdint.h>
#include <vector>

namespace {

    /**
     * This function rotates the given argument left by the given number
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
            (arg << bits)
            | (arg >> (32 - bits))
        );
    }

}

namespace Hash {

    std::vector< uint8_t > Md5(const std::vector< uint8_t >& data) {
        // This a straightforward implementation of the pseudocode
        // found in the Wikipedia page for MD5
        // (https://en.wikipedia.org/wiki/MD5).
        static size_t s[64] = {
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        };
        static uint32_t K[64] = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };
        uint8_t chunk[64];
        uint32_t M[16];
        uint32_t a0 = 0x67452301;
        uint32_t b0 = 0xEFCDAB89;
        uint32_t c0 = 0x98BADCFE;
        uint32_t d0 = 0x10325476;
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
                    chunk[56] = (uint8_t)ml;
                    chunk[57] = (uint8_t)(ml >> 8);
                    chunk[58] = (uint8_t)(ml >> 16);
                    chunk[59] = (uint8_t)(ml >> 24);
                    chunk[60] = (uint8_t)(ml >> 32);
                    chunk[61] = (uint8_t)(ml >> 40);
                    chunk[62] = (uint8_t)(ml >> 48);
                    chunk[63] = (uint8_t)(ml >> 56);
                }
            }
            for (size_t i = 0; i < 16; ++i) {
                M[i] = (
                    (uint32_t)chunk[i * 4 + 0]
                    | ((uint32_t)chunk[i * 4 + 1] << 8)
                    | ((uint32_t)chunk[i * 4 + 2] << 16)
                    | ((uint32_t)chunk[i * 4 + 3] << 24)
                );
            }
            uint32_t A = a0;
            uint32_t B = b0;
            uint32_t C = c0;
            uint32_t D = d0;
            for (size_t i = 0; i < 64; ++i) {
                uint32_t F;
                size_t g;
                if (i < 16) {
                    F = (B & C) | ((~B) & D);
                    g = i;
                } else if (i < 32) {
                    F = (D & B) | ((~D) & C);
                    g = (5 * i + 1) % 16;
                } else if (i < 48) {
                    F = B ^ C ^ D;
                    g = (3 * i + 5) % 16;
                } else {
                    F = C ^ (B | (~D));
                    g = (7 * i) % 16;
                }
                F = F + A + K[i] + M[g];
                A = D;
                D = C;
                C = B;
                B = B + Rot(F, s[i]);
            }
            a0 += A;
            b0 += B;
            c0 += C;
            d0 += D;
        }
        return {
            (uint8_t)(a0 & 0xff),
            (uint8_t)((a0 >> 8) & 0xff),
            (uint8_t)((a0 >> 16) & 0xff),
            (uint8_t)((a0 >> 24) & 0xff),
            (uint8_t)(b0 & 0xff),
            (uint8_t)((b0 >> 8) & 0xff),
            (uint8_t)((b0 >> 16) & 0xff),
            (uint8_t)((b0 >> 24) & 0xff),
            (uint8_t)(c0 & 0xff),
            (uint8_t)((c0 >> 8) & 0xff),
            (uint8_t)((c0 >> 16) & 0xff),
            (uint8_t)((c0 >> 24) & 0xff),
            (uint8_t)(d0 & 0xff),
            (uint8_t)((d0 >> 8) & 0xff),
            (uint8_t)((d0 >> 16) & 0xff),
            (uint8_t)((d0 >> 24) & 0xff),
        };
    }

}
