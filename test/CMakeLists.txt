# CMakeLists.txt for HashTests
#
# © 2018 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This HashTests)

option(SHA1_TESTS_INSANELY_LONG_TEST_VECTOR "Include insanely long test vector (takes 20+ seconds unoptimized)" OFF)

set(Sources
    src/HmacTests.cpp
    src/Md5Tests.cpp
    src/Pbkdf2Tests.cpp
    src/Sha1Tests.cpp
    src/Sha2Tests.cpp
)

add_executable(${This} ${Sources})
set_target_properties(${This} PROPERTIES
    FOLDER Tests
)

if(SHA1_TESTS_INSANELY_LONG_TEST_VECTOR)
    target_compile_definitions(${This} PRIVATE INCLUDE_INSANELY_LONG_TEST_VECTOR)
endif(SHA1_TESTS_INSANELY_LONG_TEST_VECTOR)

target_include_directories(${This} PRIVATE ..)

target_link_libraries(${This} PUBLIC
    gtest_main
    Hash
)

add_test(
    NAME ${This}
    COMMAND ${This}
)
