/**
 * @file Hmac.cpp
 *
 * This module contains the implementation of the functions which can be used
 * to make HMAC-computing functions based on given hash functions.
 *
 * © 2018 by Richard Walters
 */

#include <algorithm>
#include <iomanip>
#include <Hash/Hmac.hpp>
#include <sstream>
#include <string.h>
#include <stdint.h>
#include <vector>

namespace {

    /**
     * This function returns a string of raw character codes that has the same
     * data as the given vector of bytes.
     *
     * @param[in] input
     *     This is the data to convert into a string of raw character codes.
     *
     * @return
     *     A string of raw character codes equivalent to the given vector of
     *     bytes is returned.
     */
    std::string BytesToRawString(const std::vector< uint8_t >& input) {
        return std::string{
            input.begin(),
            input.end()
        };
    }

    /**
     * This function returns a string of hex digits that has the same
     * data as the given vector of bytes.
     *
     * @param[in] input
     *     This is the data to convert into a string of raw character codes.
     *
     * @return
     *     A string of hex digits  equivalent to the given vector of
     *     bytes is returned.
     */
    std::string BytesToHexString(const std::vector< uint8_t >& input) {
        std::ostringstream codeStringBuilder;
        codeStringBuilder << std::hex << std::setfill('0');
        for (auto codeByte: input) {
            codeStringBuilder << std::setw(2) << (int)codeByte;
        }
        return codeStringBuilder.str();
    }

    /**
     * This function returns a vector of bytes that has the same data as the
     * given string of raw character codes.
     *
     * @param[in] input
     *     This is the data (raw character codes) to convert into a vector
     *     of bytes.
     *
     * @return
     *     A vector of bytes equivalent to the given string of raw character
     *     codes is returned.
     */
    std::vector< uint8_t > RawStringToBytes(const std::string& input) {
        std::vector< uint8_t > dataAsVector(input.length());
        if (!dataAsVector.empty()) {
            (void)memcpy(dataAsVector.data(), input.c_str(), dataAsVector.size());
        }
        return dataAsVector;
    }

    /**
     * This function returns a vector of bytes that has the same data as the
     * given string of hex digits.
     *
     * @param[in] input
     *     This is the data (hex digits) to convert into a vector
     *     of bytes.
     *
     * @return
     *     A vector of bytes equivalent to the given string of hex digits
     *     is returned.
     */
    std::vector< uint8_t > HexStringToBytes(const std::string& input) {
        std::vector< uint8_t > dataAsVector(input.length() / 2);
        for (size_t i = 0; i < dataAsVector.size(); ++i) {
            auto& byte = dataAsVector[i];
            for (auto digit: input.substr(i * 2, 2)) {
                byte <<= 4;
                if ((digit >= '0') && (digit <= '9')) {
                    byte += (uint8_t)(digit - '0');
                } else if ((digit >= 'a') && (digit <= 'f')) {
                    byte += (uint8_t)((digit - 'a') + 10);
                }
            }
        }
        return dataAsVector;
    }

    /**
     * This function concatenates together two vectors of bytes.
     *
     * @param[in] lhs
     *     This is the left-hand vector to concatenate.
     *
     * @param[in] rhs
     *     This is the right-hand vector to concatenate.
     *
     * @return
     *     The vector formed by concatenating the two given vectors together
     *     is returned.
     */
    std::vector< uint8_t > operator+ (
        const std::vector< uint8_t >& lhs,
        const std::vector< uint8_t >& rhs
    ) {
        std::vector< uint8_t > result(lhs.size() + rhs.size());
        std::copy(
            lhs.begin(),
            lhs.end(),
            result.begin()
        );
        std::copy(
            rhs.begin(),
            rhs.end(),
            result.begin() + lhs.size()
        );
        return result;
    }

}

namespace Hash {

    std::function<
        std::string(
            const std::vector< uint8_t >&,
            const std::vector< uint8_t >&
        )
    > MakeHmacBytesToStringFunction(
        std::function< std::string(const std::vector< uint8_t >&) > hashFunction,
        size_t blockSize
    ) {
        const auto innerHash = [hashFunction](const std::vector< uint8_t >& input) {
            const auto data = hashFunction(input);
            return HexStringToBytes(data);
        };
        const auto innerHmac = MakeHmacBytesToBytesFunction(
            innerHash,
            blockSize
        );
        return [innerHmac](
            const std::vector< uint8_t >& key,
            const std::vector< uint8_t >& message
        ){
            const auto code = innerHmac(key, message);
            return BytesToHexString(code);
        };
    }

    std::function<
        std::string(
            const std::string&,
            const std::string&
        )
    > MakeHmacStringToStringFunction(
        std::function< std::string(const std::string&) > hashFunction,
        size_t blockSize
    ) {
        const auto innerHash = [hashFunction](const std::vector< uint8_t >& input) {
            const auto inputAsString = BytesToRawString(input);
            const auto data = hashFunction(inputAsString);
            return HexStringToBytes(data);
        };
        const auto innerHmac = MakeHmacBytesToBytesFunction(
            innerHash,
            blockSize
        );
        return [innerHmac](
            const std::string& key,
            const std::string& message
        ){
            const auto keyAsBytes = RawStringToBytes(key);
            const auto messageAsBytes = RawStringToBytes(message);
            const auto code = innerHmac(keyAsBytes, messageAsBytes);
            return BytesToHexString(code);
        };
    }

    std::function<
        std::vector< uint8_t >(
            const std::vector< uint8_t >&,
            const std::vector< uint8_t >&
        )
    > MakeHmacBytesToBytesFunction(
        std::function< std::vector< uint8_t >(const std::vector< uint8_t >&) > hashFunction,
        size_t blockSize
    ) {
        return [hashFunction, blockSize](
            const std::vector< uint8_t >& key,
            const std::vector< uint8_t >& message
        ) {
            std::vector< uint8_t > normalizedKey(key);
            if (normalizedKey.size() > blockSize) {
                normalizedKey = hashFunction(normalizedKey);
            }
            normalizedKey.resize(blockSize);
            std::vector< uint8_t > opad(normalizedKey);
            for (auto& b: opad) {
                b ^= 0x5C;
            }
            std::vector< uint8_t > ipad(normalizedKey);
            for (auto& b: ipad) {
                b ^= 0x36;
            }
            return hashFunction(opad + hashFunction(ipad + message));
        };
    }

    std::function<
        std::vector< uint8_t >(
            const std::string&,
            const std::string&
        )
    > MakeHmacStringToBytesFunction(
        std::function< std::vector< uint8_t >(const std::string&) > hashFunction,
        size_t blockSize
    ) {
        const auto innerHash = [hashFunction](const std::vector< uint8_t >& input) {
            const auto inputAsString = BytesToRawString(input);
            const auto data = hashFunction(inputAsString);
            return data;
        };
        const auto innerHmac = MakeHmacBytesToBytesFunction(
            innerHash,
            blockSize
        );
        return [innerHmac](
            const std::string& key,
            const std::string& message
        ){
            const auto keyAsBytes = RawStringToBytes(key);
            const auto messageAsBytes = RawStringToBytes(message);
            const auto code = innerHmac(keyAsBytes, messageAsBytes);
            return code;
        };
    }

}
