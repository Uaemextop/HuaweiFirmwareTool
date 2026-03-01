cmake_minimum_required(VERSION 3.12)

project(huawei_firmware_tools LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Build options ────────────────────────────────────────────────────────────
option(ENABLE_MBEDTLS  "Link against mbedTLS (required for encrypt/decrypt)"  ON)
option(BUILD_WLAN_AES  "Build libwlan_aes_crypto shared library"               ON)
option(BUILD_CFGTOOL   "Build cfgtool XML config utility"                      ON)
option(BUILD_EFUSE     "Build eFuse key derivation library"                    ON)
option(BUILD_AESCRYPT2 "Build aescrypt2 (XML encrypt/decrypt)"                 ON)

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

# ── cfgtool (standalone self-contained binary) ──────────────────────────────
# Single binary: cfgtool + XML engine (libxml2) + OS stubs.
# Embeds decompiled code from libhw_ssp_basic.so (XML ops) and
# libsmp_api.so (CFGTOOL path ops) so it works without the router runtime.
if(BUILD_CFGTOOL)
    find_package(LibXml2 REQUIRED)

    add_executable(cfgtool
        cfgtool/cfgtool.c
        cfgtool/cfgtool_xml.c
        stubs/hw_os_stubs.c
    )
    target_include_directories(cfgtool PRIVATE
        cfgtool stubs ${LIBXML2_INCLUDE_DIRS}
    )
    target_compile_definitions(cfgtool PRIVATE STANDALONE_CFGTOOL)
    target_link_libraries(cfgtool PRIVATE ${LIBXML2_LIBRARIES})
    install(TARGETS cfgtool RUNTIME DESTINATION bin)
endif()

# ── aescrypt2 (unified self-contained binary) ───────────────────────────────
# Single binary: aescrypt2 + crypto + efuse + stubs.  Accepts XML input/output.
# Automatically gzip-compresses before encrypt, gunzip-decompresses after decrypt.
if(BUILD_AESCRYPT2)
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

# ── Standalone tools (no external deps, cross-platform) ─────────────────────
# Decompiled from original Huawei firmware binaries.
# Each tool embeds all necessary library code for standalone operation.

# Each tool has its own directory with all library code embedded inline.
# No external router libraries (libhw_ssp_basic.so, libsmp_api.so, etc.) needed.

# getfilecrc – CRC32 file integrity checker
# Original: /bin/getfilecrc (9392 bytes), NEEDED: libc.so only (zero HW_ imports)
add_executable(getfilecrc getfilecrc/getfilecrc.c)
install(TARGETS getfilecrc RUNTIME DESTINATION bin)

# ontinfo – ONT device information query
# Original: /bin/ontinfo (9500 bytes), NEEDED: libhw_ssp_basic.so, libsmp_api.so
# Embedded: HW_DM_PDGetAttr (reads hw_boardinfo), HW_OS_Printf, HW_OS_StrLen
add_executable(ontinfo ontinfo/ontinfo.c)
install(TARGETS ontinfo RUNTIME DESTINATION bin)

# setboardinfo – hw_boardinfo field editor
# Original: /bin/setboardinfo (13636 bytes), NEEDED: libhw_smp_dm_pdt.so, libpolarssl.so
# Embedded: DM_SaveBoardInfo, DM_LoadBoardInfo, HW_OS_List*, HW_OS_AESDecrypt_Ex
add_executable(setboardinfo setboardinfo/setboardinfo.c)
install(TARGETS setboardinfo RUNTIME DESTINATION bin)

# ConvertLog2Dst – Binary log to text converter
# Original: /bin/ConvertLog2Dst (9500 bytes), NEEDED: libhw_ssp_basic.so
# Embedded: HW_OS_Fopen/Fclose/Fgets/Fwrite, HW_TIMER_TimeToDSTStr
add_executable(ConvertLog2Dst ConvertLog2Dst/ConvertLog2Dst.c)
install(TARGETS ConvertLog2Dst RUNTIME DESTINATION bin)

# cominfo – Process/component info query
# Original: /bin/cominfo (9524 bytes), NEEDED: libhw_ssp_basic.so
# Embedded: HW_OS_Printf, HW_OS_StrLen, HW_OS_BaseName, COMM_* API
add_executable(cominfo cominfo/cominfo.c)
install(TARGETS cominfo RUNTIME DESTINATION bin)

# hw_qoe_getloid – Get device LOID
# Original: /bin/hw_qoe_getloid (5456 bytes), NEEDED: libhw_ssp_basic.so
# Embedded: HW_DM_PDGetAttr, HW_OS_StrCaseCmp
add_executable(hw_qoe_getloid hw_qoe_getloid/hw_qoe_getloid.c)
install(TARGETS hw_qoe_getloid RUNTIME DESTINATION bin)

# hw_qoe_getpppaccount – Get PPP credentials
# Original: /bin/hw_qoe_getpppaccount (9500 bytes), NEEDED: libcfg_api.so, libhw_ssp_basic.so
# Embedded: HW_DM_PDGetAttr, HW_OS_StrCaseCmp, WAN_IF_GetPppWanAccountInfo
add_executable(hw_qoe_getpppaccount hw_qoe_getpppaccount/hw_qoe_getpppaccount.c)
install(TARGETS hw_qoe_getpppaccount RUNTIME DESTINATION bin)

# decrypt_boardinfo – Decrypt AES-128-CBC encrypted hw_boardinfo files
# Original: /bin/decrypt_boardinfo (5404 bytes), NEEDED: libhw_smp_dm_pdt.so, libpolarssl.so
# Embedded: DM_DecryptBoardInfo → AES-128-CBC (full implementation, key from .rodata)
add_executable(decrypt_boardinfo decrypt_boardinfo/decrypt_boardinfo.c)
install(TARGETS decrypt_boardinfo RUNTIME DESTINATION bin)

# kmc_tool – KMC key store file manager
# Original: /bin/kmc_tool (9500 bytes), NEEDED: libhw_ssp_basic.so
# Embedded: KMC_MKExsit, KMC_CheckHashEnd, WsecGetVersion, HW_OS_CopyFile, HW_OS_Fopen/Fclose
add_executable(kmc_tool kmc_tool/kmc_tool.c)
install(TARGETS kmc_tool RUNTIME DESTINATION bin)

# keyfilemng – Key file backup/check/restore manager
# Original: /bin/keyfilemng (21936 bytes), NEEDED: libhw_smp_dm_pdt.so, libsmp_api.so, libhw_ssp_basic.so
# Embedded: CRC32, HW_OS_* file ops, DM_DecryptBoardInfo, SwmBackUpKeyDataDirect
add_executable(keyfilemng keyfilemng/keyfilemng.c)
install(TARGETS keyfilemng RUNTIME DESTINATION bin)

# decrypt_prvtkey – Decrypt encrypted PEM private keys (prvt.key, plugprvt.key)
# Decompiled from: libhw_ssp_ssl.so + libhw_ssp_basic.so + libpolarssl.so
# Embedded: AES-256-CBC, MD5, base64, EVP_BytesToKey, PEM parsing (all inline)
add_executable(decrypt_prvtkey decrypt_prvtkey/decrypt_prvtkey.c)
install(TARGETS decrypt_prvtkey RUNTIME DESTINATION bin)

# backupKey – MTD flash partition key backup tool
# Original: /bin/backupKey (9500 bytes), NEEDED: libhw_ssp_basic.so, libhw_ldsp_common.so
# Embedded: TOOL_GetMTDNameByKeyWord, SwmReleaseKeyData, HW_OS_ReadFile, HW_OS_ExecShellCmdEx
add_executable(backupKey backupKey/backupKey.c)
install(TARGETS backupKey RUNTIME DESTINATION bin)

# ── Install ──────────────────────────────────────────────────────────────────
if(BUILD_WLAN_AES AND NOT WIN32)
    install(TARGETS wlan_aes_crypto LIBRARY DESTINATION lib)
endif()
install(FILES
    aescrypt2/hw_ssp_aescrypt.h
    DESTINATION include/huawei
)
