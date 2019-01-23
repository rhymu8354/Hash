#ifndef HASH_PBKDF2_HPP
#define HASH_PBKDF2_HPP

/**
 * @file Pbkdf2.hpp
 *
 * This module declares the PBKDF2 (Password-Based Key Derivation Function 2),
 * described here: https://en.wikipedia.org/wiki/PBKDF2
 *
 * © 2019 by Richard Walters
 */

#include <functional>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace Hash {

    /**
     * This is an implementation of the PBKDF2 (Password-Based Key Derivation
     * Function 2), described here: https://en.wikipedia.org/wiki/PBKDF2.
     *
     * @param[in] prf
     *     This is a pseudorandom function of two parameters with output
     *     length hLen (e.g., a keyed HMAC)
     *
     * @param[in] hLen
     *     This is the output length, in bits, of the PRF.
     *
     * @param[in] password
     *     This is the master password from which a derived key is generated.
     *
     * @param[in] salt
     *     This is a sequence of bits, known as a cryptographic salt
     *     (https://en.wikipedia.org/wiki/Salt_(cryptography)).
     *
     * @param[in] c
     *     This is the number of iterations desired.
     *
     * @param[in] dkLen
     *     This is the desired byte-length of the derived key.
     *
     * @return
     *     The generated derived key is returned.
     */
    std::vector< uint8_t > Pbkdf2(
        std::function<
            std::vector< uint8_t >(
                const std::vector< uint8_t >&,
                const std::vector< uint8_t >&
            )
        > prf,
        size_t hLen,
        const std::vector< uint8_t >& password,
        const std::vector< uint8_t >& salt,
        size_t c,
        size_t dkLen
    );

}

#endif /* HASH_PBKDF2_HPP */
