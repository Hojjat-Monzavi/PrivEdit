# ===========================================================================
#  MinGW-w64 toolchain file
#
#  Default install root: C:/msys64/mingw64
#  Override by passing -DMINGW_ROOT=<path> on the cmake command line.
# ===========================================================================

set(CMAKE_SYSTEM_NAME      Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

if(NOT DEFINED MINGW_ROOT)
    if(EXISTS "C:/msys64/mingw64/bin/x86_64-w64-mingw32-g++.exe")
        set(MINGW_ROOT "C:/msys64/mingw64" CACHE PATH "MinGW-w64 root")
    elseif(EXISTS "C:/mingw64/bin/x86_64-w64-mingw32-g++.exe")
        set(MINGW_ROOT "C:/mingw64"        CACHE PATH "MinGW-w64 root")
    else()
        message(FATAL_ERROR
            "MinGW-w64 root not found. Pass -DMINGW_ROOT=<path> "
            "or install to C:/msys64/mingw64.")
    endif()
else()
    set(MINGW_ROOT "${MINGW_ROOT}" CACHE PATH "MinGW-w64 root" FORCE)
endif()

set(_triple x86_64-w64-mingw32)

set(CMAKE_C_COMPILER   "${MINGW_ROOT}/bin/${_triple}-gcc.exe")
set(CMAKE_CXX_COMPILER "${MINGW_ROOT}/bin/${_triple}-g++.exe")
set(CMAKE_RC_COMPILER  "${MINGW_ROOT}/bin/windres.exe")
set(CMAKE_AR           "${MINGW_ROOT}/bin/${_triple}-ar.exe")
set(CMAKE_RANLIB       "${MINGW_ROOT}/bin/${_triple}-ranlib.exe")
set(CMAKE_STRIP        "${MINGW_ROOT}/bin/${_triple}-strip.exe")

set(CMAKE_FIND_ROOT_PATH "${MINGW_ROOT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Prefer the static archives over the import stubs.
set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".dll.a")

# OpenSSL and zlib in MSYS2 are found via pkg-config; make sure
# CMake is looking at the right one.
set(ENV{PKG_CONFIG_PATH} "${MINGW_ROOT}/lib/pkgconfig")

# No compiler feature tests over SSH etc. -- keep it simple.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)