#pragma once

/**
 * @file Md5.hpp
 *
 * This module declares the MD5 hash function and block size.
 *
 * © 2019 by Richard Walters
 */

#include <stddef.h>
#include <stdint.h>
#include <vector>

namespace Hash {

    /**
     * This is the block size, in bytes, used by the MD5 hash function.
     */
    constexpr size_t MD5_BLOCK_SIZE = 64;

    /**
     * This is the size, in bits, of the digest produced  by the MD5 hash
     * function.
     */
    constexpr size_t MD5_DIGEST_LENGTH = 128;

    /**
     * This function computes the MD5 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The MD5 message digest of the given data is returned
     *     as a vector of bytes.
     */
    std::vector< uint8_t > Md5(const std::vector< uint8_t >& data);

}
