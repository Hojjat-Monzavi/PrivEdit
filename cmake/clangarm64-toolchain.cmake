# MSYS2 CLANGARM64 toolchain for native ARM64 Windows builds.
#
# Usage (inside the MSYS2 CLANGARM64 shell):
#
#   cmake -S . -B build -G Ninja \
#         -DCMAKE_BUILD_TYPE=Release \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/clangarm64-toolchain.cmake

set(CMAKE_SYSTEM_NAME      Windows)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER   clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_RC_COMPILER  windres)
set(CMAKE_AR           llvm-ar)
set(CMAKE_RANLIB       llvm-ranlib)
set(CMAKE_STRIP        llvm-strip)

if(NOT DEFINED CLANGARM64_ROOT)
    if(EXISTS "C:/msys64/clangarm64")
        set(CLANGARM64_ROOT "C:/msys64/clangarm64" CACHE PATH "CLANGARM64 root")
    elseif(EXISTS "/clangarm64")
        set(CLANGARM64_ROOT "/clangarm64" CACHE PATH "CLANGARM64 root")
    else()
        message(FATAL_ERROR
            "Could not locate the MSYS2 CLANGARM64 prefix. "
            "Pass -DCLANGARM64_ROOT=<path> or run inside the CLANGARM64 shell.")
    endif()
endif()

set(CMAKE_FIND_ROOT_PATH "${CLANGARM64_ROOT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".dll.a")

set(ENV{PKG_CONFIG_PATH} "${CLANGARM64_ROOT}/lib/pkgconfig")

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)