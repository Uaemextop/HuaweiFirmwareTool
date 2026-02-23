cmake_minimum_required(VERSION 3.12)

project(hw_fmw LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(hw_fmw hw_fmw.cpp)
add_executable(hw_sign hw_sign.cpp)
add_executable(hw_verify hw_verify.cpp)
add_executable(hw_flash hw_flash.cpp)

add_library(util STATIC util_hw.cpp util_rsa.cpp util.cpp)

find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
  target_link_libraries(util OpenSSL::Crypto)
endif(OPENSSL_FOUND)

find_package(ZLIB REQUIRED)
if (ZLIB_FOUND)
  target_link_libraries(util ZLIB::ZLIB)
endif(ZLIB_FOUND)

# https://en.cppreference.com/w/cpp/filesystem
# GNU implementation prior to 9.1 requires linking with -lstdc++fs
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.1")
  target_link_libraries(util stdc++fs)
endif()

target_link_libraries(hw_fmw PRIVATE util)
target_link_libraries(hw_sign PRIVATE util)
target_link_libraries(hw_verify PRIVATE util)
target_link_libraries(hw_flash PRIVATE util)

# Windows socket library for hw_flash
if (WIN32)
  target_link_libraries(hw_flash PRIVATE ws2_32)
endif()

