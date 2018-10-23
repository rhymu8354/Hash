#ifndef HASH_SHA2_HPP
#define HASH_SHA2_HPP

/**
 * @file Sha2.hpp
 *
 * This module declares the SHA-2 hash functions and block sizes.
 *
 * © 2018 by Richard Walters
 */

#include <stddef.h>
#include <stdint.h>
#include <vector>

namespace Hash {

    /**
     * This is the block size, in bytes, used by the SHA-224 hash function.
     */
    constexpr size_t SHA224_BLOCK_SIZE = 64;

    /**
     * This is the block size, in bytes, used by the SHA-256 hash function.
     */
    constexpr size_t SHA256_BLOCK_SIZE = 64;

    /**
     * This is the block size, in bytes, used by the SHA-512 hash function.
     */
    constexpr size_t SHA512_BLOCK_SIZE = 128;

    /**
     * This function computes the SHA-224 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA-224 message digest of the given data is returned
     *     as a vector of bytes.
     */
    std::vector< uint8_t > Sha224(const std::vector< uint8_t >& data);

    /**
     * This function computes the SHA-256 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA-256 message digest of the given data is returned
     *     as a vector of bytes.
     */
    std::vector< uint8_t > Sha256(const std::vector< uint8_t >& data);

    /**
     * This function computes the SHA-512 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA-512 message digest of the given data is returned
     *     as a vector of bytes.
     */
    std::vector< uint8_t > Sha512(const std::vector< uint8_t >& data);

}

#endif /* HASH_SHA2_HPP */
