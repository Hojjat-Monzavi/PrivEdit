# ===========================================================================
#  Cross-compile toolchain: x86_64-w64-mingw32
#
#  DO NOT pass this file when building inside the MSYS2 MINGW64 shell.
#  In that environment the compiler, ar, ranlib, windres, and pkg-config
#  are already on PATH and CMake finds them automatically:
#
#      cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
#
#  Use this file only when the host is not MSYS2 (e.g. Linux or macOS)
#  and the mingw-w64 cross toolchain is installed system-wide.
# ===========================================================================

set(CMAKE_SYSTEM_NAME      Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Let CMake auto-detect the compiler from PATH. If your cross toolchain is
# prefixed differently, set it explicitly:
#
#     set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)
#     set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
#     set(CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres)

# Let pkg-config resolve the cross-compiled libraries.
set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/usr/x86_64-w64-mingw32/lib/pkgconfig")