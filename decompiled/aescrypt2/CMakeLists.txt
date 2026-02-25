# Reconstructed aescrypt2 — Decompiled from Huawei EG8145V5 firmware
#
# Build:
#   cmake -B build -S .
#   cmake --build build
#
# Requires: mbedTLS development libraries (libmbedtls-dev)

cmake_minimum_required(VERSION 3.12)

project(aescrypt2_decompiled LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Sources ──────────────────────────────────────────────────────────────────

add_executable(aescrypt2
    aescrypt2.c
    aes.c
)

target_include_directories(aescrypt2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# ── mbedTLS ──────────────────────────────────────────────────────────────────
# Try CMake config first; fall back to pkg-config.

find_package(MbedTLS QUIET)
if(MbedTLS_FOUND)
    target_link_libraries(aescrypt2 PRIVATE MbedTLS::mbedcrypto)
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(MBEDCRYPTO QUIET mbedcrypto)
    endif()

    if(MBEDCRYPTO_FOUND)
        target_include_directories(aescrypt2 PRIVATE ${MBEDCRYPTO_INCLUDE_DIRS})
        target_link_libraries(aescrypt2 PRIVATE ${MBEDCRYPTO_LIBRARIES})
        target_link_directories(aescrypt2 PRIVATE ${MBEDCRYPTO_LIBRARY_DIRS})
    else()
        # Direct link — works on Debian/Ubuntu with libmbedtls-dev installed
        target_link_libraries(aescrypt2 PRIVATE mbedcrypto)
    endif()
endif()

# ── Compiler warnings ───────────────────────────────────────────────────────

target_compile_options(aescrypt2 PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)
