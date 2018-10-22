#ifndef HASH_HASH_HPP
#define HASH_HASH_HPP

/**
 * @file Hash.hpp
 *
 * This module declares the Hash::Hash class template.
 *
 * © 2018 by Richard Walters
 */

#include <functional>
#include <stdint.h>
#include <string>
#include <vector>

namespace Hash {

    typedef std::vector< uint8_t >(*HashFunction)(const std::vector< uint8_t >&);

    /**
     * This function computes the message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The SHA1 message digest of the given data is returned
     *     as a string of hexadecimal digits.
     */
    template< HashFunction hash > std::string BytesToString(const std::vector< uint8_t >& data) {
        const auto digest = hash(data);
        std::ostringstream digestStringBuilder;
        digestStringBuilder << std::hex << std::setfill('0');
        for (auto digestByte: digest) {
            digestStringBuilder << std::setw(2) << (int)digestByte;
        }
        return digestStringBuilder.str();
    }

    /**
     * This function computes the message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The message digest of the given data is returned
     *     as a string of hexadecimal digits.
     */
    template< HashFunction hash > std::string StringToString(const std::string& data) {
        std::vector< uint8_t > dataAsVector(data.length());
        if (!dataAsVector.empty()) {
            (void)memcpy(dataAsVector.data(), data.c_str(), dataAsVector.size());
        }
        return BytesToString< hash >(dataAsVector);
    }

    /**
     * This function computes the message digest of the given data.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The message digest of the given data is returned
     *     as a vector of bytes.
     */
    template< HashFunction hash > std::vector< uint8_t > StringToBytes(const std::string& data) {
        std::vector< uint8_t > dataAsVector(data.length());
        if (!dataAsVector.empty()) {
            (void)memcpy(dataAsVector.data(), data.c_str(), dataAsVector.size());
        }
        return hash(dataAsVector);
    }

}

#endif /* HASH_HASH_HPP */
