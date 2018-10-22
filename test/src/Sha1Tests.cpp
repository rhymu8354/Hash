/**
 * @file Sha1Tests.cpp
 *
 * This module contains the unit tests of the Sha1 functions.
 *
 * © 2018 by Richard Walters
 */

#include <gtest/gtest.h>
#include <Hash/Sha1.hpp>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <sstream>
#include <vector>

TEST(Sha1Tests, HashTestVectors) {
    // These test vectors were taken from:
    // https://www.di-mgt.com.au/sha_testvectors.html
    struct TestVector {
        std::string input;
        std::string output;
    };
    const std::vector< TestVector > testVectors{
        {"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "a49b2446a02c645bf419f995b67091253a04a259"},
        {std::string(1000000, 'a'), "34aa973cd4c4daa4f61eeb2bdbad27316534016f"},
    };
    for (const auto& testVector: testVectors) {
        EXPECT_EQ(
            testVector.output,
            Hash::Sha1StringToString(testVector.input)
        );
    }
}

#ifdef INCLUDE_INSANELY_LONG_TEST_VECTOR
TEST(Sha1Tests, HashInsanelyLongInput) {
    // This test vector was taken from:
    // https://www.di-mgt.com.au/sha_testvectors.html
    const std::string baseString = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
    std::ostringstream builder;
    for (size_t i = 0; i < 16777216; ++i) {
        builder << baseString;
    }
    EXPECT_EQ(
        "7789f0c9ef7bfc40d93311143dfbe69e2017f592",
        Hash::Sha1StringToString(builder.str())
    );
}
#endif /* INCLUDE_INSANELY_LONG_TEST_VECTOR */

TEST(Sha1Tests, HashToByteVector) {
    EXPECT_EQ(
        (std::vector< uint8_t >{
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
            0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
        }),
        Hash::Sha1StringToBytes("abc")
    );
}
