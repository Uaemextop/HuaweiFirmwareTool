# CMake toolchain file for cross-compiling to aarch64 using Clang
# This works with the system Clang (no separate cross-compiler needed) and
# is particularly suitable for building Termux-compatible aarch64 binaries.
#
# Prerequisites:
#   sudo apt install clang lld llvm \
#                    libssl-dev:arm64 zlib1g-dev:arm64
#   (Enable arm64 multiarch first: sudo dpkg --add-architecture arm64)
#
# Usage:
#   cmake /path/to/cpp \
#       -DCMAKE_TOOLCHAIN_FILE=/path/to/cpp/cmake/toolchain-aarch64-clang.cmake \
#       -DCMAKE_BUILD_TYPE=Release
#   make -j$(nproc)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

find_program(CLANG_CC  clang)
find_program(CLANG_CXX clang++)

if(NOT CLANG_CC OR NOT CLANG_CXX)
    message(FATAL_ERROR
        "Clang not found.\n"
        "Install with: sudo apt install clang")
endif()

set(CMAKE_C_COMPILER   ${CLANG_CC})
set(CMAKE_CXX_COMPILER ${CLANG_CXX})

# Tell Clang to target aarch64-linux-gnu
set(CMAKE_C_FLAGS_INIT   "--target=aarch64-linux-gnu")
set(CMAKE_CXX_FLAGS_INIT "--target=aarch64-linux-gnu")

# Use LLD as the linker (avoids needing aarch64 binutils)
set(CMAKE_EXE_LINKER_FLAGS_INIT    "-fuse-ld=lld --target=aarch64-linux-gnu")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld --target=aarch64-linux-gnu")

# Search libraries/headers in the target sysroot only
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
