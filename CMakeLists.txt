# CMakeLists.txt for Hash
#
# © 2018 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This Hash)

set(Headers
    include/Hash/Hmac.hpp
    include/Hash/Sha1.hpp
    include/Hash/Sha2.hpp
)

set(Sources
    src/Hmac.cpp
    src/Sha1.cpp
    src/Sha2.cpp
)

add_library(${This} STATIC ${Sources} ${Headers})
set_target_properties(${This} PROPERTIES
    FOLDER Libraries
)

target_include_directories(${This} PUBLIC include)

add_subdirectory(test)
