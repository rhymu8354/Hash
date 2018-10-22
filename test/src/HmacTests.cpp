/**
 * @file HmacTests.cpp
 *
 * This module contains the unit tests of the Hmac functions.
 *
 * © 2018 by Richard Walters
 */

#include <gtest/gtest.h>
#include <Hash/Sha1.hpp>
#include <Hash/Hash.hpp>
#include <Hash/Hmac.hpp>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <sstream>
#include <vector>

TEST(HmacTests, HmacCodeTestVectors) {
    // These test vectors were taken from:
    // https://en.wikipedia.org/wiki/HMAC
    struct TestVector {
        std::string key;
        std::string message;
        std::string output;
    };
    const std::vector< TestVector > testVectors{
        {"lksadfjlkasfldjksajdflkasdjlfkasdjlfkasdjlfksajlkdfjalksdfjlksadfjlksad;fjlksadjflkasdjlfk", "The quick brown fox jumps over the lazy dog", "6a0fbb14e3dbe792d585935f6ff82e51ce70e1e7"},
        {"key", "The quick brown fox jumps over the lazy dog", "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"},
        {"", "", "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"},
    };
    const auto hmac = Hash::MakeHmacStringToStringFunction(Hash::StringToString< Hash::Sha1 >, 64);
    for (const auto& testVector: testVectors) {
        EXPECT_EQ(
            testVector.output,
            hmac(testVector.key, testVector.message)
        );
    }
}

TEST(HmacTests, HmacCodeByteVector) {
    const auto hmac = Hash::MakeHmacStringToBytesFunction(Hash::StringToBytes< Hash::Sha1 >, 64);
    EXPECT_EQ(
        (std::vector< uint8_t >{
            0xfb, 0xdb, 0x1d, 0x1b, 0x18, 0xaa, 0x6c, 0x08,
            0x32, 0x4b, 0x7d, 0x64, 0xb7, 0x1f, 0xb7, 0x63,
            0x70, 0x69, 0x0e, 0x1d,
        }),
        hmac("", "")
    );
}
