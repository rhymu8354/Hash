#ifndef HASH_HMAC_HPP
#define HASH_HMAC_HPP

/**
 * @file Hmac.hpp
 *
 * This module declares functions which can be used to make HMAC-computing
 * functions based on given hash functions.
 *
 * © 2018 by Richard Walters
 */

#include <functional>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace Hash {

    /**
     * This function is a factory which returns an HMAC function that takes two
     * vectors of bytes as input and produces a string output, computing the
     * HMAC code for a given key and message, using a given hash function.
     *
     * @param[in] hashFunction
     *     This is the hash function to use to compute digests in order to
     *     generate HMAC codes.
     *
     * @param[in] blockSize
     *     This is the block size of the given hash function, in bytes.
     *
     * @param[in] outputSize
     *     This is the output size of the given hash function, in bytes.
     *
     * @return
     *     A function which computes HMAC codes using the given hash function,
     *     taking byte vectors as input and producing string output is
     *     returned.
     */
    std::function<
        std::string(
            const std::vector< uint8_t >&,
            const std::vector< uint8_t >&
        )
    > MakeHmacBytesToStringFunction(
        std::function< std::string(const std::vector< uint8_t >&) > hashFunction,
        size_t blockSize,
        size_t outputSize
    );

    /**
     * This function is a factory which returns an HMAC function that takes two
     * strings as input and produces a string output, computing the
     * HMAC code for a given key and message, using a given hash function.
     *
     * @param[in] hashFunction
     *     This is the hash function to use to compute digests in order to
     *     generate HMAC codes.
     *
     * @param[in] blockSize
     *     This is the block size of the given hash function, in bytes.
     *
     * @param[in] outputSize
     *     This is the output size of the given hash function, in bytes.
     *
     * @return
     *     A function which computes HMAC codes using the given hash function,
     *     taking strings as input and producing string output is
     *     returned.
     */
    std::function<
        std::string(
            const std::string&,
            const std::string&
        )
    > MakeHmacStringToStringFunction(
        std::function< std::string(const std::string&) > hashFunction,
        size_t blockSize,
        size_t outputSize
    );

    /**
     * This function is a factory which returns an HMAC function that takes two
     * vectors of bytes as input and produces a byte vector output, computing
     * the HMAC code for a given key and message, using a given hash function.
     *
     * @param[in] hashFunction
     *     This is the hash function to use to compute digests in order to
     *     generate HMAC codes.
     *
     * @param[in] blockSize
     *     This is the block size of the given hash function, in bytes.
     *
     * @param[in] outputSize
     *     This is the output size of the given hash function, in bytes.
     *
     * @return
     *     A function which computes HMAC codes using the given hash function,
     *     taking byte vectors as input and producing byte vector output is
     *     returned.
     */
    std::function<
        std::vector< uint8_t >(
            const std::vector< uint8_t >&,
            const std::vector< uint8_t >&
        )
    > MakeHmacBytesToBytesFunction(
        std::function< std::vector< uint8_t >(const std::vector< uint8_t >&) > hashFunction,
        size_t blockSize,
        size_t outputSize
    );

    /**
     * This function is a factory which returns an HMAC function that takes two
     * strings as input and produces a byte vector output, computing
     * the HMAC code for a given key and message, using a given hash function.
     *
     * @param[in] hashFunction
     *     This is the hash function to use to compute digests in order to
     *     generate HMAC codes.
     *
     * @param[in] blockSize
     *     This is the block size of the given hash function, in bytes.
     *
     * @param[in] outputSize
     *     This is the output size of the given hash function, in bytes.
     *
     * @return
     *     A function which computes HMAC codes using the given hash function,
     *     taking strings as input and producing byte vector output is
     *     returned.
     */
    std::function<
        std::vector< uint8_t >(
            const std::string&,
            const std::string&
        )
    > MakeHmacStringToBytesFunction(
        std::function< std::vector< uint8_t >(const std::string&) > hashFunction,
        size_t blockSize,
        size_t outputSize
    );

}

#endif /* HASH_HMAC_HPP */
