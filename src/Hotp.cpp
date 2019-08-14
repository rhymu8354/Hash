/**
 * @file Hotp.cpp
 *
 * This module contains the implementation of the Hotp function used to
 * generate one-time only passwords based on the HMAC (Hash-based Message
 * Authentication Code) algorithm.
 *
 * © 2019 by Richard Walters
 */

#include <Hash/Hmac.hpp>
#include <Hash/Hotp.hpp>
#include <Hash/Templates.hpp>
#include <math.h>
#include <stdint.h>
#include <vector>

namespace {

    /**
     * Dynamically truncate the given bit string to 31 bits by taking the
     * least significant four bits of of the bit string, using them
     * as a byte index into the bit string, and returning the 31 bits
     * beginning at one bit past that offset.
     *
     * @param[in] s
     *     This is the bit string to truncate.
     *
     * @return
     *     The truncated bit string is returned.
     */
    uint32_t dt(const std::vector< uint8_t > s) {
        const auto offset = (size_t)(s[s.size() - 1] & 0xF);
        return (
            (((uint32_t)(s[offset] & 0x7F)) << 24)
            | (((uint32_t)s[offset + 1]) << 16)
            | (((uint32_t)s[offset + 2]) << 8)
            | ((uint32_t)s[offset + 3])
        );
    }

}

namespace Hash {

    int Hotp(
        HashFunction hashFunction,
        size_t blockSize,
        const std::string& secret,
        uint64_t count,
        size_t digits
    ) {
        const auto hmac = MakeHmacBytesToBytesFunction(hashFunction, blockSize);
        const std::vector< uint8_t > secretBytes(secret.begin(), secret.end());
        std::vector< uint8_t > countBytes(8);
        countBytes[0] = (uint8_t)(count >> 56);
        countBytes[1] = (uint8_t)((count >> 48) & 0xFF);
        countBytes[2] = (uint8_t)((count >> 40) & 0xFF);
        countBytes[3] = (uint8_t)((count >> 32) & 0xFF);
        countBytes[4] = (uint8_t)((count >> 24) & 0xFF);
        countBytes[5] = (uint8_t)((count >> 16) & 0xFF);
        countBytes[6] = (uint8_t)((count >> 8) & 0xFF);
        countBytes[7] = (uint8_t)(count & 0xFF);
        const auto hs = hmac(secretBytes, countBytes);
        const auto snum = dt(hs);
        return (int)(snum % ((uint32_t)round(pow(10.0, (double)digits))));
    }

}
