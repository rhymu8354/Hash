#ifndef HASH_SHA1_HPP
#define HASH_SHA1_HPP

/**
 * @file Sha1.hpp
 *
 * This module declares the Hash::Sha1 functions.
 *
 * © 2016-2018 by Richard Walters
 */

#include <stdint.h>
#include <string>
#include <vector>

namespace Hash {

    /**
     * This function computes the SHA-1 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA1 message digest of the given data is returned
     *     as a string of hexadecimal digits.
     */
    std::string Sha1BytesToString(const std::vector< uint8_t >& data);

    /**
     * This function computes the SHA-1 message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA1 message digest of the given data is returned
     *     as a string of hexadecimal digits.
     */
    std::string Sha1StringToString(const std::string& data);


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
    std::vector< uint8_t > Sha1BytesToBytes(const std::vector< uint8_t >& data);

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
    std::vector< uint8_t > Sha1StringToBytes(const std::string& data);

}

#endif /* HASH_SHA1_HPP */
