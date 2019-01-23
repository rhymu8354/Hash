/**
 * @file Pbkdf2.cpp
 *
 * This module contains the implementation of the PBKDF2 (Password-Based Key
 * Derivation Function 2), described here: https://en.wikipedia.org/wiki/PBKDF2
 *
 * © 2019 by Richard Walters
 */

#include <Hash/Pbkdf2.hpp>
#include <stdint.h>
#include <vector>

namespace {

    /**
     * Compute the xor (^) of c iterations of chained PRFs.
     *
     * @param[in] prf
     *     This is a pseudorandom function of two parameters with output
     *     length hLen (e.g., a keyed HMAC)
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
     * @param[in] i
     *     This is the index of the hLen-bit block of the derived key.
     *
     * @return
     *     The generated derived key is returned.
     */
    std::vector< uint8_t > F(
        std::function<
            std::vector< uint8_t >(
                const std::vector< uint8_t >&,
                const std::vector< uint8_t >&
            )
        > prf,
        const std::vector< uint8_t >& password,
        const std::vector< uint8_t >& salt,
        size_t c,
        size_t i
    ) {
        std::vector< uint8_t > saltWithIndex(salt);
        saltWithIndex.push_back((uint8_t)(i >> 24));
        saltWithIndex.push_back((uint8_t)(i >> 16));
        saltWithIndex.push_back((uint8_t)(i >> 8));
        saltWithIndex.push_back((uint8_t)i);
        std::vector< uint8_t > dk = prf(password, saltWithIndex);
        std::vector< uint8_t > u(dk);
        for (size_t j = 0; j < c - 1; ++j) {
            std::vector< uint8_t > uPrevious(u);
            u = prf(password, uPrevious);
            for (size_t k = 0; k < dk.size(); ++k) {
                dk[k] ^= u[k];
            }
        }
        return dk;
    }

}

namespace Hash {

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
    ) {
        std::vector< uint8_t > hash;
        hash.reserve(dkLen);
        const size_t l = (dkLen * 8 + hLen - 1) / hLen;
        for (size_t i = 0; i < l - 1; ++i) {
            const auto T = F(prf, password, salt, c, i + 1);
            hash.insert(
                hash.end(),
                T.begin(),
                T.end()
            );
        }
        const auto leftOvers = dkLen * 8 - (l - 1) * hLen;
        if (leftOvers > 0) {
            const auto T = F(prf, password, salt, c, l);
            hash.insert(
                hash.end(),
                T.begin(),
                T.begin() + (leftOvers / 8)
            );
        }
        return hash;
    }

}
