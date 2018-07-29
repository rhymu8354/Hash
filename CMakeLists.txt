# CMakeLists.txt for Sha1
#
# © 2018 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This Sha1)

set(Headers
    include/Sha1/Sha1.hpp
)

set(Sources
    src/Sha1.cpp
)

add_library(${This} STATIC ${Sources} ${Headers})
set_target_properties(${This} PROPERTIES
    FOLDER Libraries
)

target_include_directories(${This} PUBLIC include)

add_subdirectory(test)
