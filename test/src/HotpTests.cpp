/**
 * @file HotpTests.cpp
 *
 * This module contains the unit tests of the Hotp functions.
 *
 * © 2018 by Richard Walters
 */

#include <gtest/gtest.h>
#include <Hash/Sha1.hpp>
#include <Hash/Templates.hpp>
#include <Hash/Hotp.hpp>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <sstream>
#include <vector>

TEST(HotpTests, HotpCodeTestVectors) {
    // These test vectors were taken from [RFC
    // 4226](https://tools.ietf.org/html/rfc4226) Appendix D.
    const std::string secret = "12345678901234567890";
    struct TestVector {
        uint64_t count;
        int hotp;
    };
    const std::vector< TestVector > testVectors{
        {0, 755224},
        {1, 287082},
        {2, 359152},
        {3, 969429},
        {4, 338314},
        {5, 254676},
        {6, 287922},
        {7, 162583},
        {8, 399871},
        {9, 520489},
    };
    for (const auto& testVector: testVectors) {
        EXPECT_EQ(
            testVector.hotp,
            Hash::Hotp(
                Hash::Sha1,
                Hash::SHA1_BLOCK_SIZE,
                secret,
                testVector.count,
                6
            )
        );
    }
}
