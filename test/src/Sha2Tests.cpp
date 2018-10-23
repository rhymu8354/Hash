/**
 * @file Sha2Tests.cpp
 *
 * This module contains the unit tests of the Sha2 functions.
 *
 * © 2018 by Richard Walters
 */

#include <gtest/gtest.h>
#include <Hash/Templates.hpp>
#include <Hash/Sha2.hpp>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <sstream>
#include <vector>

TEST(Sha2Tests, Sha224TestVectors) {
    // These test vectors were obtained by calculating SHA-224 digests using
    // the great and powerful openssl tool.
    struct TestVector {
        std::string input;
        std::string output;
    };
    const std::vector< TestVector > testVectors{
        {"", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
        {"The quick brown fox jumps over the lazy dog", "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"},
        {std::string(1000000, 'a'), "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"},
    };
    for (const auto& testVector: testVectors) {
        EXPECT_EQ(
            testVector.output,
            Hash::StringToString< Hash::Sha224 >(testVector.input)
        );
    }
}

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

TEST(Sha2Tests, Sha512TestVectors) {
    // These test vectors were obtained by calculating SHA-512 digests using
    // the great and powerful openssl tool.
    struct TestVector {
        std::string input;
        std::string output;
    };
    const std::vector< TestVector > testVectors{
        {"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        {"The quick brown fox jumps over the lazy dog", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"},
        {std::string(1000000, 'a'), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"},
    };
    for (const auto& testVector: testVectors) {
        EXPECT_EQ(
            testVector.output,
            Hash::StringToString< Hash::Sha512 >(testVector.input)
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
