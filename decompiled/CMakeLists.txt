cmake_minimum_required(VERSION 3.12)

project(huawei_decompiled LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Build options ────────────────────────────────────────────────────────────
option(ENABLE_MBEDTLS  "Link against mbedTLS (required for encrypt/decrypt)"  ON)
option(BUILD_AESCRYPT2 "Build aescrypt2 utility"                               ON)
option(BUILD_WLAN_AES  "Build libwlan_aes_crypto shared library"               ON)
option(BUILD_CFGTOOL   "Build cfgtool XML config utility"                      ON)
option(BUILD_EFUSE     "Build eFuse key derivation library"                    ON)

# ── Toolchain hint (cross-compile for target ARM device) ────────────────────
# cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/arm-linux-musleabi.cmake -B build
# For host build (analysis/testing): cmake -B build

# ── mbedTLS ──────────────────────────────────────────────────────────────────
if(ENABLE_MBEDTLS)
    find_package(MbedTLS QUIET)
    if(NOT MbedTLS_FOUND)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(MBEDTLS QUIET mbedtls)
        endif()
    endif()

    if(MbedTLS_FOUND)
        set(MBEDTLS_LIBS MbedTLS::mbedcrypto)
        set(MBEDTLS_FOUND_FLAG TRUE)
    elseif(MBEDTLS_FOUND)
        set(MBEDTLS_LIBS ${MBEDTLS_LIBRARIES})
        set(MBEDTLS_FOUND_FLAG TRUE)
    else()
        message(STATUS "mbedTLS not found – AES operations will be stubs")
        set(MBEDTLS_FOUND_FLAG FALSE)
    endif()
endif()

# ── Stub definitions for Huawei OS helpers (host build only) ────────────────
# On the actual device these come from libhw_ssp_basic.so.
# For host compilation we provide minimal stubs so the code links.
if(NOT CMAKE_CROSSCOMPILING)
    add_library(hw_stubs STATIC
        stubs/hw_os_stubs.c
    )
    target_include_directories(hw_stubs PUBLIC stubs)
    set_target_properties(hw_stubs PROPERTIES POSITION_INDEPENDENT_CODE ON)
    set(HW_STUB_LIB hw_stubs)
else()
    set(HW_STUB_LIB "")
endif()

# ── libwlan_aes_crypto ───────────────────────────────────────────────────────
if(BUILD_WLAN_AES)
    add_library(wlan_aes_crypto SHARED
        wlan_aes/wlan_aes_crypto.c
    )
    target_include_directories(wlan_aes_crypto PUBLIC wlan_aes)

    if(MBEDTLS_FOUND_FLAG)
        target_compile_definitions(wlan_aes_crypto PRIVATE HAVE_MBEDTLS)
        target_link_libraries(wlan_aes_crypto PRIVATE ${MBEDTLS_LIBS})
    endif()
    if(HW_STUB_LIB)
        target_link_libraries(wlan_aes_crypto PRIVATE ${HW_STUB_LIB})
    endif()

    set_target_properties(wlan_aes_crypto PROPERTIES
        OUTPUT_NAME "wlan_aes_crypto"
        VERSION     1.0.0
        SOVERSION   1
    )
endif()

# ── hw_ssp_aescrypt (static helper lib used by aescrypt2) ───────────────────
add_library(hw_ssp_aescrypt STATIC
    aescrypt2/hw_ssp_aescrypt.c
)
target_include_directories(hw_ssp_aescrypt PUBLIC aescrypt2)
if(MBEDTLS_FOUND_FLAG)
    target_compile_definitions(hw_ssp_aescrypt PRIVATE HAVE_MBEDTLS)
    target_link_libraries(hw_ssp_aescrypt PRIVATE ${MBEDTLS_LIBS})
endif()
if(HW_STUB_LIB)
    target_link_libraries(hw_ssp_aescrypt PRIVATE ${HW_STUB_LIB})
endif()

# ── aescrypt2 executable ─────────────────────────────────────────────────────
if(BUILD_AESCRYPT2)
    add_executable(aescrypt2
        aescrypt2/aescrypt2.c
    )
    target_include_directories(aescrypt2 PRIVATE stubs)
    target_link_libraries(aescrypt2 PRIVATE hw_ssp_aescrypt)
    if(HW_STUB_LIB)
        target_link_libraries(aescrypt2 PRIVATE ${HW_STUB_LIB})
    endif()
    if(MBEDTLS_FOUND_FLAG)
        target_compile_definitions(aescrypt2 PRIVATE HAVE_MBEDTLS)
        target_link_libraries(aescrypt2 PRIVATE ${MBEDTLS_LIBS})
    endif()
endif()

# ── std::filesystem / stdc++fs compatibility ─────────────────────────────────
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_C_COMPILER_VERSION VERSION_LESS "9.0")
    target_link_libraries(hw_ssp_aescrypt PRIVATE stdc++fs)
endif()

# ── Install rules ────────────────────────────────────────────────────────────
if(BUILD_AESCRYPT2)
    install(TARGETS aescrypt2 RUNTIME DESTINATION bin)
endif()
if(BUILD_WLAN_AES)
    install(TARGETS wlan_aes_crypto LIBRARY DESTINATION lib)
endif()
install(FILES
    aescrypt2/hw_ssp_aescrypt.h
    wlan_aes/wlan_aes_crypto.h
    efuse/hal_efuse.h
    efuse/dm_key.h
    cfgtool/hw_cfg_tool.h
    DESTINATION include/huawei
)

# ── libdm_efuse (eFuse key derivation) ──────────────────────────────────────
if(BUILD_EFUSE)
    add_library(dm_efuse STATIC
        efuse/hal_efuse.c
        efuse/dm_key.c
    )
    target_include_directories(dm_efuse PUBLIC efuse PRIVATE stubs)
    if(MBEDTLS_FOUND_FLAG)
        target_compile_definitions(dm_efuse PRIVATE HAVE_MBEDTLS)
        target_link_libraries(dm_efuse PRIVATE ${MBEDTLS_LIBS})
    endif()
    if(HW_STUB_LIB)
        target_link_libraries(dm_efuse PRIVATE ${HW_STUB_LIB})
    endif()
endif()

# ── cfgtool XML configuration utility ───────────────────────────────────────
if(BUILD_CFGTOOL)
    add_executable(cfgtool
        cfgtool/cfgtool.c
    )
    if(HW_STUB_LIB)
        target_link_libraries(cfgtool PRIVATE ${HW_STUB_LIB})
    endif()
    install(TARGETS cfgtool RUNTIME DESTINATION bin)
endif()
