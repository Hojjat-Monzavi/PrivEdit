# ===========================================================================
#  Cross-compile toolchain: aarch64-w64-mingw32 via LLVM-MinGW
#
#  DO NOT pass this file when building inside the MSYS2 CLANGARM64 shell.
#  In that environment CMake auto-detects clang, llvm-ar, llvm-ranlib,
#  llvm-strip, windres, and pkg-config from PATH:
#
#      cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
#
#  Use this file only with an external LLVM-MinGW installation, e.g. the
#  release from https://github.com/mstorsjo/llvm-mingw. Build libsodium
#  and zlib for aarch64-w64-mingw32 first, then point PKG_CONFIG_PATH at
#  their .pc files.
# ===========================================================================

set(CMAKE_SYSTEM_NAME      Windows)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Adjust if your LLVM-MinGW prefix differs.
set(CMAKE_C_COMPILER   aarch64-w64-mingw32-clang)
set(CMAKE_CXX_COMPILER aarch64-w64-mingw32-clang++)
set(CMAKE_RC_COMPILER  aarch64-w64-mingw32-windres)
set(CMAKE_AR           llvm-ar)
set(CMAKE_RANLIB       llvm-ranlib)
set(CMAKE_STRIP        llvm-strip)

# Point pkg-config at the cross-built .pc files.
set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/opt/llvm-mingw/aarch64/lib/pkgconfig")