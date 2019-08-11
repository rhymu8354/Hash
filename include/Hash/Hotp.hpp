#pragma once

/**
 * @file Hotp.hpp
 *
 * This module declares the Hotp function used to generate one-time only
 * passwords based on the HMAC (Hash-based Message Authentication Code)
 * algorithm.
 *
 * © 2019 by Richard Walters
 */

#include "Templates.hpp"

#include <stddef.h>
#include <stdint.h>
#include <string>

namespace Hash {

    /**
     * Generate a one-time password using the HMAC (Hash-based Message
     * Authentication Code) algorithm with the given hash function,
     * block size, shared secret, and counter value, according to
     * the HOTP (HMAC-Based One-Time Password) algorithm defined
     * in [RFC 4226](https://tools.ietf.org/html/rfc4226).
     *
     * @param[in] hashFunction
     *     This is the hash function to use to compute digests.
     *
     * @param[in] blockSize
     *     This is the block size of the given hash function, in bytes.
     *
     * @param[in] secret
     *     This is the shared secret to use to generate the one-time password.
     *
     * @param[in] count
     *     This is the counter value to use to generate the one-time password.
     *
     * @param[in] digits
     *     This is the number of digits to produce for the one-time password.
     *
     * @return
     *     The generated one-time password is returned.
     */
    int Hotp(
        HashFunction hashFunction,
        size_t blockSize,
        const std::string& secret,
        uint64_t count,
        size_t digits
    );

}
