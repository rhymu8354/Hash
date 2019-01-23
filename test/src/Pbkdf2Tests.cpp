/**
 * @file Pbkdf2Tests.cpp
 *
 * This module contains the unit tests of the Pbkdf2 functions.
 *
 * © 2018 by Richard Walters
 */

#include <gtest/gtest.h>
#include <Hash/Sha1.hpp>
#include <Hash/Sha2.hpp>
#include <Hash/Templates.hpp>
#include <Hash/Hmac.hpp>
#include <Hash/Pbkdf2.hpp>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <sstream>
#include <vector>

TEST(Pbkdf2Tests, Pbkdf2TestVectors) {
    // These test vectors were taken from:
    // https://en.wikipedia.org/wiki/PBKDF2
    struct TestVector {
        std::function<
            std::vector< uint8_t >(
                const std::vector< uint8_t >&,
                const std::vector< uint8_t >&
            )
        > prf;
        size_t hLen;
        std::string password;
        std::vector< uint8_t > salt;
        size_t c;
        size_t dkLen;
        std::vector< uint8_t > output;
    };
    const std::vector< TestVector > testVectors{
        // This one came from the Wikipedia article
        // (https://en.wikipedia.org/wiki/PBKDF2)
        {
            Hash::MakeHmacBytesToBytesFunction(
                Hash::Sha1,
                Hash::SHA1_BLOCK_SIZE
            ),
            Hash::SHA1_DIGEST_LENGTH,
            "plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd",
            std::vector< uint8_t >({
                0xA0, 0x09, 0xC1, 0xA4, 0x85, 0x91, 0x2C, 0x6A,
                0xE6, 0x30, 0xD3, 0xE7, 0x44, 0x24, 0x0B, 0x04,
            }),
            1000,
            16,
            std::vector< uint8_t >({
                0x17, 0xEB, 0x40, 0x14, 0xC8, 0xC4, 0x61, 0xC3,
                0x00, 0xE9, 0xB6, 0x15, 0x18, 0xB9, 0xA1, 0x8B,
            }),
        },

        // The following came from RFC 6070
        // (https://tools.ietf.org/html/rfc6070)
        {
            Hash::MakeHmacBytesToBytesFunction(
                Hash::Sha1,
                Hash::SHA1_BLOCK_SIZE
            ),
            Hash::SHA1_DIGEST_LENGTH,
            "password",
            std::vector< uint8_t >({
                0x73, 0x61, 0x6c, 0x74, // "salt"
            }),
            1,
            20,
            std::vector< uint8_t >({
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
                0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
                0x2f, 0xe0, 0x37, 0xa6,
            }),
        },
        {
            Hash::MakeHmacBytesToBytesFunction(
                Hash::Sha1,
                Hash::SHA1_BLOCK_SIZE
            ),
            Hash::SHA1_DIGEST_LENGTH,
            "password",
            std::vector< uint8_t >({
                0x73, 0x61, 0x6c, 0x74, // "salt"
            }),
            2,
            20,
            std::vector< uint8_t >({
                0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
                0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
                0xd8, 0xde, 0x89, 0x57,
            }),
        },
        {
            Hash::MakeHmacBytesToBytesFunction(
                Hash::Sha1,
                Hash::SHA1_BLOCK_SIZE
            ),
            Hash::SHA1_DIGEST_LENGTH,
            "password",
            std::vector< uint8_t >({
                0x73, 0x61, 0x6c, 0x74, // "salt"
            }),
            4096,
            20,
            std::vector< uint8_t >({
                0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
                0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
                0x65, 0xa4, 0x29, 0xc1,
            }),
        },
        {
            Hash::MakeHmacBytesToBytesFunction(
                Hash::Sha1,
                Hash::SHA1_BLOCK_SIZE
            ),
            Hash::SHA1_DIGEST_LENGTH,
            "passwordPASSWORDpassword",
            std::vector< uint8_t >({
                // "saltSALTsaltSALTsaltSALTsaltSALTsalt"
                0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54,
                0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54,
                0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54,
                0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54,
                0x73, 0x61, 0x6c, 0x74,
            }),
            4096,
            25,
            std::vector< uint8_t >({
                0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
                0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
                0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
                0x38,
            }),
        },
        {
            Hash::MakeHmacBytesToBytesFunction(
                Hash::Sha1,
                Hash::SHA1_BLOCK_SIZE
            ),
            Hash::SHA1_DIGEST_LENGTH,
            std::string("pass\0word", 9),
            std::vector< uint8_t >({
                // "sa\0lt"
                0x73, 0x61, 0x00, 0x6c, 0x74,
            }),
            4096,
            16,
            std::vector< uint8_t >({
                0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
                0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3,
            }),
        },
        {
            Hash::MakeHmacBytesToBytesFunction(
                Hash::Sha256,
                Hash::SHA256_BLOCK_SIZE
            ),
            256,
            std::string("password", 9),
            std::vector< uint8_t >({
                0x73, 0x61, 0x6c, 0x74, // "salt"
            }),
            1,
            32,
            std::vector< uint8_t >({
                0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
                0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
                0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
                0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
            }),
        },
        {
            Hash::MakeHmacBytesToBytesFunction(
                Hash::Sha256,
                Hash::SHA256_BLOCK_SIZE
            ),
            256,
            std::string("password", 9),
            std::vector< uint8_t >({
                0x73, 0x61, 0x6c, 0x74, // "salt"
            }),
            2,
            32,
            std::vector< uint8_t >({
                0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
                0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
                0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
                0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43,
            }),
        },
        {
            Hash::MakeHmacBytesToBytesFunction(
                Hash::Sha256,
                Hash::SHA256_BLOCK_SIZE
            ),
            256,
            std::string("password", 9),
            std::vector< uint8_t >({
                0x73, 0x61, 0x6c, 0x74, // "salt"
            }),
            4096,
            32,
            std::vector< uint8_t >({
                0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
                0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
                0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
                0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a,
            }),
        },
    };
    size_t iteration = 0;
    for (const auto& testVector: testVectors) {
        ++iteration;
        const std::vector< uint8_t > passwordBytes(
            testVector.password.begin(),
            testVector.password.end()
        );
        EXPECT_EQ(
            testVector.output,
            Hash::Pbkdf2(
                testVector.prf,
                testVector.hLen,
                passwordBytes,
                testVector.salt,
                testVector.c,
                testVector.dkLen
            )
        ) << "Iteration #" << iteration;
    }
}
