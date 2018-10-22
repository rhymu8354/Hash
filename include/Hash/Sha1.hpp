#ifndef HASH_SHA1_HPP
#define HASH_SHA1_HPP

/**
 * @file Sha1.hpp
 *
 * This module declares the SHA-1 hash function and block size.
 *
 * © 2016-2018 by Richard Walters
 */

#include <stddef.h>
#include <stdint.h>
#include <vector>

namespace Hash {

    /**
     * This is the block size, in bytes, used by the SHA-1 hash function.
     */
    constexpr size_t SHA1_BLOCK_SIZE = 64;

    /**
     * This function computes the SHA-1 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA1 message digest of the given data is returned
     *     as a vector of bytes.
     */
    std::vector< uint8_t > Sha1(const std::vector< uint8_t >& data);

}

#endif /* HASH_SHA1_HPP */
