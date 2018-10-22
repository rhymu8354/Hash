#ifndef SHA1_SHA1_HPP
#define SHA1_SHA1_HPP

/**
 * @file Sha1.hpp
 *
 * This module declares the Sha1::Sha1 functions.
 *
 * © 2016-2018 by Richard Walters
 */

#include <stdint.h>
#include <string>
#include <vector>

namespace Sha1 {

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
    std::string Sha1String(const std::vector< uint8_t >& data);

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
    std::string Sha1String(const std::string& data);


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
    std::vector< uint8_t > Sha1Bytes(const std::vector< uint8_t >& data);

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
    std::vector< uint8_t > Sha1Bytes(const std::string& data);

}

#endif /* SHA1_SHA1_HPP */
