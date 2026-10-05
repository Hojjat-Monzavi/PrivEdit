# MinGW-w64 toolchain

`mingw64-toolchain.cmake` points CMake at a MinGW-w64 installation,
defaulting to `C:/msys64/mingw64`. Override with `-DMINGW_ROOT=...`.

Prerequisites in MSYS2 (MinGW 64-bit shell):

    pacman -S mingw-w64-x86_64-gcc
    pacman -S mingw-w64-x86_64-cmake
    pacman -S mingw-w64-x86_64-openssl
    pacman -S mingw-w64-x86_64-zlib
    pacman -S mingw-w64-x86_64-pkgconf