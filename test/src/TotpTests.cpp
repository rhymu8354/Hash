/**
 * @file TotpTests.cpp
 *
 * This module contains the unit tests of the Totp functions.
 *
 * © 2018 by Richard Walters
 */

#include <gtest/gtest.h>
#include <Hash/Sha1.hpp>
#include <Hash/Sha2.hpp>
#include <Hash/Templates.hpp>
#include <Hash/Totp.hpp>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <sstream>
#include <vector>

TEST(TotpTests, TotpCodeTestVectors) {
    // These test vectors were taken from [RFC
    // 6238](https://tools.ietf.org/html/rfc6238) Appendix B.
    const uint64_t step = 30;
    const uint64_t base = 0;
    struct TestVector {
        const std::string secret;
        uint64_t time;
        int totp;
        Hash::HashFunction hashFunction;
        size_t blockSize;
    };
    const std::vector< TestVector > testVectors{
        {"12345678901234567890", 59, 94287082, Hash::Sha1, Hash::SHA1_BLOCK_SIZE},
        {"12345678901234567890123456789012", 59, 46119246, Hash::Sha256, Hash::SHA256_BLOCK_SIZE},
        {"1234567890123456789012345678901234567890123456789012345678901234", 59, 90693936, Hash::Sha512, Hash::SHA512_BLOCK_SIZE},
        {"12345678901234567890", 1111111109, 7081804, Hash::Sha1, Hash::SHA1_BLOCK_SIZE},
        {"12345678901234567890123456789012", 1111111109, 68084774, Hash::Sha256, Hash::SHA256_BLOCK_SIZE},
        {"1234567890123456789012345678901234567890123456789012345678901234", 1111111109, 25091201, Hash::Sha512, Hash::SHA512_BLOCK_SIZE},
        {"12345678901234567890", 1111111111, 14050471, Hash::Sha1, Hash::SHA1_BLOCK_SIZE},
        {"12345678901234567890123456789012", 1111111111, 67062674, Hash::Sha256, Hash::SHA256_BLOCK_SIZE},
        {"1234567890123456789012345678901234567890123456789012345678901234", 1111111111, 99943326, Hash::Sha512, Hash::SHA512_BLOCK_SIZE},
        {"12345678901234567890", 1234567890, 89005924, Hash::Sha1, Hash::SHA1_BLOCK_SIZE},
        {"12345678901234567890123456789012", 1234567890, 91819424, Hash::Sha256, Hash::SHA256_BLOCK_SIZE},
        {"1234567890123456789012345678901234567890123456789012345678901234", 1234567890, 93441116, Hash::Sha512, Hash::SHA512_BLOCK_SIZE},
        {"12345678901234567890", 2000000000, 69279037, Hash::Sha1, Hash::SHA1_BLOCK_SIZE},
        {"12345678901234567890123456789012", 2000000000, 90698825, Hash::Sha256, Hash::SHA256_BLOCK_SIZE},
        {"1234567890123456789012345678901234567890123456789012345678901234", 2000000000, 38618901, Hash::Sha512, Hash::SHA512_BLOCK_SIZE},
        {"12345678901234567890", 20000000000, 65353130, Hash::Sha1, Hash::SHA1_BLOCK_SIZE},
        {"12345678901234567890123456789012", 20000000000, 77737706, Hash::Sha256, Hash::SHA256_BLOCK_SIZE},
        {"1234567890123456789012345678901234567890123456789012345678901234", 20000000000, 47863826, Hash::Sha512, Hash::SHA512_BLOCK_SIZE},
    };
    for (const auto& testVector: testVectors) {
        EXPECT_EQ(
            testVector.totp,
            Hash::Totp(
                testVector.hashFunction,
                testVector.blockSize,
                testVector.secret,
                testVector.time,
                base,
                step,
                8
            )
        );
    }
}
