/**
 * @file Totp.cpp
 *
 * This module contains the implementation of the Totp function used to
 * generate one-time only passwords based on the HMAC (Hash-based Message
 * Authentication Code) algorithm.
 *
 * © 2019 by Richard Walters
 */

#include <Hash/Hotp.hpp>
#include <Hash/Totp.hpp>
#include <stdint.h>

namespace Hash {

    int Totp(
        HashFunction hashFunction,
        size_t blockSize,
        const std::string& secret,
        uint64_t time,
        uint64_t base,
        uint64_t step,
        size_t digits
    ) {
        const auto t = (time - base) / step;
        return Hotp(hashFunction, blockSize, secret, t, digits);
    }

}
