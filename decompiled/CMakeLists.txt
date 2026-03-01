cmake_minimum_required(VERSION 3.12)

project(huawei_firmware_tools LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Build options ────────────────────────────────────────────────────────────
option(ENABLE_MBEDTLS  "Link against mbedTLS (required for encrypt/decrypt)"  ON)
option(BUILD_AESCRYPT2 "Build aescrypt2 utility"                               ON)
option(BUILD_WLAN_AES  "Build libwlan_aes_crypto shared library"               ON)
option(BUILD_CFGTOOL   "Build cfgtool XML config utility"                      ON)
option(BUILD_EFUSE     "Build eFuse key derivation library"                    ON)
option(BUILD_STANDALONE "Build unified standalone aescrypt2 binary (default)"   ON)

# ── Platform detection ───────────────────────────────────────────────────────
if(WIN32)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    # Windows CRT provides strcpy_s etc.
    add_compile_definitions(__STDC_LIB_EXT1__=1)
endif()

# ── mbedTLS ──────────────────────────────────────────────────────────────────
if(ENABLE_MBEDTLS)
    # Try CMake package first
    find_package(MbedTLS QUIET CONFIG)
    if(MbedTLS_FOUND AND TARGET MbedTLS::mbedcrypto)
        set(MBEDTLS_LIBS MbedTLS::mbedcrypto)
        set(MBEDTLS_FOUND_FLAG TRUE)
        message(STATUS "mbedTLS found via CMake package")
    else()
        # Try pkg-config
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(MBEDCRYPTO QUIET mbedcrypto)
        endif()
        if(MBEDCRYPTO_FOUND)
            set(MBEDTLS_LIBS ${MBEDCRYPTO_LIBRARIES})
            include_directories(${MBEDCRYPTO_INCLUDE_DIRS})
            link_directories(${MBEDCRYPTO_LIBRARY_DIRS})
            set(MBEDTLS_FOUND_FLAG TRUE)
            message(STATUS "mbedTLS found via pkg-config: ${MBEDCRYPTO_LIBRARIES}")
        else()
            # Direct fallback: find library and header manually
            find_library(MBEDCRYPTO_LIB NAMES mbedcrypto)
            find_path(MBEDTLS_INC NAMES mbedtls/aes.h)
            if(MBEDCRYPTO_LIB AND MBEDTLS_INC)
                set(MBEDTLS_LIBS ${MBEDCRYPTO_LIB})
                include_directories(${MBEDTLS_INC})
                set(MBEDTLS_FOUND_FLAG TRUE)
                message(STATUS "mbedTLS found manually: ${MBEDCRYPTO_LIB}")
            else()
                message(STATUS "mbedTLS not found – AES operations will be stubs")
                set(MBEDTLS_FOUND_FLAG FALSE)
            endif()
        endif()
    endif()
endif()

# ── Stub definitions for Huawei OS helpers (host build) ──────────────────────
# On device these come from libhw_ssp_basic.so; on host we use stubs.
if(NOT CMAKE_CROSSCOMPILING OR WIN32)
    add_library(hw_stubs STATIC
        stubs/hw_os_stubs.c
    )
    target_include_directories(hw_stubs PUBLIC stubs)
    set_target_properties(hw_stubs PROPERTIES POSITION_INDEPENDENT_CODE ON)
    if(MBEDTLS_FOUND_FLAG)
        target_compile_definitions(hw_stubs PRIVATE HAVE_MBEDTLS)
        target_link_libraries(hw_stubs PRIVATE ${MBEDTLS_LIBS})
    endif()
    set(HW_STUB_LIB hw_stubs)
else()
    set(HW_STUB_LIB "")
endif()

# ── Helper macro ─────────────────────────────────────────────────────────────
macro(target_add_deps tgt)
    if(MBEDTLS_FOUND_FLAG)
        target_compile_definitions(${tgt} PRIVATE HAVE_MBEDTLS)
        target_link_libraries(${tgt} PRIVATE ${MBEDTLS_LIBS})
    endif()
    if(HW_STUB_LIB)
        target_link_libraries(${tgt} PRIVATE ${HW_STUB_LIB})
    endif()
endmacro()

# ── libwlan_aes_crypto (shared lib, Linux only) ─────────────────────────────
if(BUILD_WLAN_AES AND NOT WIN32)
    add_library(wlan_aes_crypto SHARED
        wlan_aes/wlan_aes_crypto.c
    )
    target_include_directories(wlan_aes_crypto PUBLIC wlan_aes)
    target_add_deps(wlan_aes_crypto)
    set_target_properties(wlan_aes_crypto PROPERTIES
        OUTPUT_NAME "wlan_aes_crypto"
        VERSION     1.0.0
        SOVERSION   1
    )
endif()

# ── hw_ssp_aescrypt (static helper lib, used when not building standalone) ──
add_library(hw_ssp_aescrypt STATIC
    aescrypt2/hw_ssp_aescrypt.c
)
target_include_directories(hw_ssp_aescrypt PUBLIC aescrypt2 stubs)
target_add_deps(hw_ssp_aescrypt)

# ── libdm_efuse (eFuse key derivation) ──────────────────────────────────────
if(BUILD_EFUSE)
    add_library(dm_efuse STATIC
        efuse/hal_efuse.c
        efuse/dm_key.c
    )
    target_include_directories(dm_efuse PUBLIC efuse PRIVATE stubs)
    target_add_deps(dm_efuse)
endif()

# ── cfgtool ─────────────────────────────────────────────────────────────────
if(BUILD_CFGTOOL)
    add_executable(cfgtool
        cfgtool/cfgtool.c
    )
    target_include_directories(cfgtool PRIVATE stubs)
    if(HW_STUB_LIB)
        target_link_libraries(cfgtool PRIVATE ${HW_STUB_LIB})
    endif()
    install(TARGETS cfgtool RUNTIME DESTINATION bin)
endif()

# ── aescrypt2 (unified self-contained binary) ───────────────────────────────
# Single binary: aescrypt2 + crypto + efuse + stubs.  Accepts XML input/output.
# Automatically gzip-compresses before encrypt, gunzip-decompresses after decrypt.
if(BUILD_STANDALONE)
    find_package(ZLIB REQUIRED)

    add_executable(aescrypt2
        aescrypt2/aescrypt2.c
        aescrypt2/hw_ssp_aescrypt.c
        efuse/hal_efuse.c
        efuse/dm_key.c
        stubs/hw_os_stubs.c
    )
    target_include_directories(aescrypt2 PRIVATE
        aescrypt2 efuse stubs
    )
    target_compile_definitions(aescrypt2 PRIVATE STANDALONE_BUILD)
    if(MBEDTLS_FOUND_FLAG)
        target_compile_definitions(aescrypt2 PRIVATE HAVE_MBEDTLS)
        target_link_libraries(aescrypt2 PRIVATE ${MBEDTLS_LIBS})
    endif()
    target_link_libraries(aescrypt2 PRIVATE ZLIB::ZLIB)
    if(WIN32)
        target_link_libraries(aescrypt2 PRIVATE ws2_32)
    endif()
    install(TARGETS aescrypt2 RUNTIME DESTINATION bin)
endif()

# ── Install ──────────────────────────────────────────────────────────────────
if(BUILD_WLAN_AES AND NOT WIN32)
    install(TARGETS wlan_aes_crypto LIBRARY DESTINATION lib)
endif()
install(FILES
    aescrypt2/hw_ssp_aescrypt.h
    DESTINATION include/huawei
)
