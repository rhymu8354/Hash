#pragma once

/**
 * @file Totp.hpp
 *
 * This module declares the Totp function used to generate one-time only
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
     * block size, shared secret, and UNIX time, according to
     * the TOTP (Time-Based One-Time Password) algorithm defined
     * in [RFC 6238](https://tools.ietf.org/html/rfc6238).
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
     * @param[in] time
     *     This is the UNIX time to use to generate the one-time password.
     *
     * @param[in] base
     *     This is the UNIX time to start counting time steps.
     *
     * @param[in] step
     *     This is the time step in seconds.
     *
     * @param[in] digits
     *     This is the number of digits to produce for the one-time password.
     *
     * @return
     *     The generated one-time password is returned.
     */
    int Totp(
        HashFunction hashFunction,
        size_t blockSize,
        const std::string& secret,
        uint64_t time,
        uint64_t base,
        uint64_t step,
        size_t digits
    );

}
