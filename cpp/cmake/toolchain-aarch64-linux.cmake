# CMake toolchain file for cross-compiling to aarch64 Linux (arm64)
# Compatible with Termux on Android/aarch64 and generic aarch64 Linux.
#
# Prerequisites (Debian/Ubuntu):
#   sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
#                    libssl-dev:arm64 zlib1g-dev:arm64
#   (Enable arm64 multiarch first: sudo dpkg --add-architecture arm64)
#
# Usage:
#   cmake /path/to/cpp \
#       -DCMAKE_TOOLCHAIN_FILE=/path/to/cpp/cmake/toolchain-aarch64-linux.cmake \
#       -DCMAKE_BUILD_TYPE=Release
#   make -j$(nproc)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Cross-compiler binaries (aarch64-linux-gnu toolchain)
find_program(CROSS_C_COMPILER   aarch64-linux-gnu-gcc)
find_program(CROSS_CXX_COMPILER aarch64-linux-gnu-g++)

if(CROSS_C_COMPILER AND CROSS_CXX_COMPILER)
    set(CMAKE_C_COMPILER   ${CROSS_C_COMPILER})
    set(CMAKE_CXX_COMPILER ${CROSS_CXX_COMPILER})
else()
    message(FATAL_ERROR
        "aarch64-linux-gnu toolchain not found.\n"
        "Install with: sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu")
endif()

# Search libraries/headers in the target sysroot only
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
