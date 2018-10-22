#ifndef HASH_SHA2_HPP
#define HASH_SHA2_HPP

/**
 * @file Sha2.hpp
 *
 * This module declares the Hash::Sha2 functions.
 *
 * © 2018 by Richard Walters
 */

#include <stdint.h>
#include <string>
#include <vector>

namespace Hash {

    /**
     * This function computes the SHA-256 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA-256 message digest of the given data is returned
     *     as a string of hexadecimal digits.
     */
    std::string Sha256BytesToString(const std::vector< uint8_t >& data);

    /**
     * This function computes the SHA-1 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA-256 message digest of the given data is returned
     *     as a string of hexadecimal digits.
     */
    std::string Sha256StringToString(const std::string& data);

    /**
     * This function computes the SHA-1 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA-256 message digest of the given data is returned
     *     as a vector of bytes.
     */
    std::vector< uint8_t > Sha256BytesToBytes(const std::vector< uint8_t >& data);

    /**
     * This function computes the SHA-1 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA-256 message digest of the given data is returned
     *     as a vector of bytes.
     */
    std::vector< uint8_t > Sha256StringToBytes(const std::string& data);

}

#endif /* HASH_SHA2_HPP */
