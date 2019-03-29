/**
 * @file Md5Tests.cpp
 *
 * This module contains the unit tests of the Md5 functions.
 *
 * © 2019 by Richard Walters
 */

#include <gtest/gtest.h>
#include <Hash/Md5.hpp>
#include <Hash/Templates.hpp>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <sstream>
#include <vector>

TEST(Md5Tests, HashTestVectors) {
    // These test vectors were taken from:
    // https://www.di-mgt.com.au/sha_testvectors.html
    struct TestVector {
        std::string input;
        std::string output;
    };
    const std::vector< TestVector > testVectors{
        {"The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"},
        {"The quick brown fox jumps over the lazy dog.", "e4d909c290d0fb1ca068ffaddf22cbd0"},
        {"", "d41d8cd98f00b204e9800998ecf8427e"},
        {"a", "0cc175b9c0f1b6a831c399e269772661"},
    };
    for (const auto& testVector: testVectors) {
        EXPECT_EQ(
            testVector.output,
            Hash::StringToString< Hash::Md5 >(testVector.input)
        );
    }
}
