cmake_minimum_required(VERSION 3.12)

project(hw_fmw LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(hw_fmw hw_fmw.cpp)
add_executable(hw_sign hw_sign.cpp)
add_executable(hw_verify hw_verify.cpp)

add_library(util STATIC util_hw.cpp util_rsa.cpp util.cpp)

# ── OpenSSL ──────────────────────────────────────────────────────────────────
# Try CMake's built-in finder first; fall back to pkg-config (used by Termux).
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    target_link_libraries(util OpenSSL::Crypto)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENSSL REQUIRED openssl)
    target_include_directories(util PRIVATE ${OPENSSL_INCLUDE_DIRS})
    target_link_libraries(util ${OPENSSL_LIBRARIES})
    target_link_directories(util PUBLIC ${OPENSSL_LIBRARY_DIRS})
endif()

# ── zlib ─────────────────────────────────────────────────────────────────────
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
    target_link_libraries(util ZLIB::ZLIB)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ZLIB REQUIRED zlib)
    target_include_directories(util PRIVATE ${ZLIB_INCLUDE_DIRS})
    target_link_libraries(util ${ZLIB_LIBRARIES})
    target_link_directories(util PUBLIC ${ZLIB_LIBRARY_DIRS})
endif()

# ── std::filesystem linkage ───────────────────────────────────────────────────
# GCC < 9  → needs -lstdc++fs   (separate library)
# Clang < 9 → needs -lc++fs     (separate library)
# GCC ≥ 9 and Clang ≥ 9: std::filesystem is part of the standard library.
# Termux uses a recent Clang where no extra link flag is needed.
# https://en.cppreference.com/w/cpp/filesystem
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0")
    target_link_libraries(util stdc++fs)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND
       CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0")
    target_link_libraries(util c++fs)
endif()

target_link_libraries(hw_fmw PRIVATE util)
target_link_libraries(hw_sign PRIVATE util)
target_link_libraries(hw_verify PRIVATE util)

