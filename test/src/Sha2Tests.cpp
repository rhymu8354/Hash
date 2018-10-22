/**
 * @file Sha2Tests.cpp
 *
 * This module contains the unit tests of the Sha2 functions.
 *
 * © 2018 by Richard Walters
 */

#include <gtest/gtest.h>
#include <Hash/Hash.hpp>
#include <Hash/Sha2.hpp>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <sstream>
#include <vector>

TEST(Sha2Tests, Sha256TestVectors) {
    // These test vectors were obtained by calculating SHA-256 digests using
    // the great and powerful openssl tool.
    struct TestVector {
        std::string input;
        std::string output;
    };
    const std::vector< TestVector > testVectors{
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
        {std::string(1000000, 'a'), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
    };
    for (const auto& testVector: testVectors) {
        EXPECT_EQ(
            testVector.output,
            Hash::StringToString< Hash::Sha256 >(testVector.input)
        );
    }
}

TEST(Sha2Tests, Sha256HashToByteVector) {
    EXPECT_EQ(
        (std::vector< uint8_t >{
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        }),
        Hash::StringToBytes< Hash::Sha256 >("")
    );
}
