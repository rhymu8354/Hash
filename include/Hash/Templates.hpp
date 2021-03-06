#ifndef HASH_TEMPLATES_HPP
#define HASH_TEMPLATES_HPP

/**
 * @file Templates.hpp
 *
 * This module declares function templates that can be used with hash
 * functions to adapt them to be more flexible in input/output types.
 *
 * © 2018 by Richard Walters
 */

#include <iomanip>
#include <sstream>
#include <stdint.h>
#include <string>
#include <string.h>
#include <vector>

namespace Hash {

    /**
     * This is the required signature of hash functions to fit into the
     * function templates found in this module.
     *
     * @param[in] message
     *     This is the message for which to compute a digest.
     *
     * @return
     *     The message digest is returned.
     */
    using HashFunction = std::vector< uint8_t >(*)(const std::vector< uint8_t >& message);

    /**
     * This function template is used to compute the message digest of the
     * given data and return it as a string of hex digits.
     *
     * @param[in] data
     *     This is the data for which to compute the message digest.
     *
     * @return
     *     The message digest of the given data is returned
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
     * This function template is used to compute the message digest of the
     * given string data and return it as a string of hex digits.
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
     * This function template is used to compute the message digest of the
     * given string data and return it as a byte vector.
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

#endif /* HASH_TEMPLATES_HPP */
