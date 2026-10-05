# ===========================================================================
#  PrivEdit GUI -- CMake build for Windows (Windows 7 - 11)
#
#  Dependencies:
#     libsodium   -- Argon2id + XChaCha20-Poly1305
#     zlib        -- payload compression
#
#  Build inside an MSYS2 shell (MINGW64 for x64, CLANGARM64 for ARM64):
#
#     cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
#     cmake --build build --parallel
#
#  A toolchain file is NOT needed inside MSYS2. Only pass one when
#  cross-compiling from a non-MinGW host (see cmake/).
# ===========================================================================

cmake_minimum_required(VERSION 3.20)

project(PrivEdit
        VERSION   1.0.0
        LANGUAGES CXX RC)

# ---------------------------------------------------------------------------
#  Platform sanity
# ---------------------------------------------------------------------------
if(NOT WIN32)
    message(FATAL_ERROR "PrivEdit GUI is Windows-only.")
endif()

# ---------------------------------------------------------------------------
#  Language settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD           17)
set(CMAKE_CXX_STANDARD_REQUIRED  ON)
set(CMAKE_CXX_EXTENSIONS         OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
#  Options
# ---------------------------------------------------------------------------
option(PRIVEDIT_LTO       "Enable link-time optimization"          ON)
option(PRIVEDIT_STRIP     "Strip the final binary (Release only)"   ON)
option(PRIVEDIT_HARDENING "Enable linker hardening flags"           ON)

# ---------------------------------------------------------------------------
#  Dependencies
#
#  pkg-config gives us the correct include dirs and library dirs for the
#  active MSYS2 environment. We then resolve the STATIC archives explicitly
#  and link by absolute path, so the import libraries (.dll.a) can never
#  win the race.
#
#  This avoids two classes of failure seen on MinGW-w64 + MSYS2:
#    1. find_package(ZLIB) ignores the cross-compile prefix on CLANGARM64.
#    2. `-lsodium` resolves to libsodium.dll.a even with `-static`.
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(ZLIB   REQUIRED IMPORTED_TARGET zlib)

# Resolve the .a archives by absolute path. HINTS covers both the
# pkg-config-reported libdir and the MSYS2 convention.
find_library(SODIUM_STATIC_LIB
    NAMES libsodium.a
    HINTS ${SODIUM_LIBDIR} ${SODIUM_LIBRARY_DIRS}
    NO_DEFAULT_PATH)
find_library(ZLIB_STATIC_LIB
    NAMES libz.a
    HINTS ${ZLIB_LIBDIR} ${ZLIB_LIBRARY_DIRS}
    NO_DEFAULT_PATH)

if(NOT SODIUM_STATIC_LIB)
    message(FATAL_ERROR
        "libsodium.a not found. Install the static archive:\n"
        "  pacman -S mingw-w64-${MSYSTEM_PREFIX}-libsodium")
endif()
if(NOT ZLIB_STATIC_LIB)
    message(FATAL_ERROR
        "libz.a not found. Install the static archive:\n"
        "  pacman -S mingw-w64-${MSYSTEM_PREFIX}-zlib")
endif()

message(STATUS "libsodium   : ${SODIUM_VERSION}  (${SODIUM_STATIC_LIB})")
message(STATUS "zlib        : ${ZLIB_VERSION}  (${ZLIB_STATIC_LIB})")

# ---------------------------------------------------------------------------
#  Sources
# ---------------------------------------------------------------------------
set(PRIVEDIT_SOURCES
    src/privedit_gui.cpp
    src/privedit.rc
)
set(PRIVEDIT_HEADERS
    src/privedit_crypto.h
    src/resource.h
    src/privedit.manifest
)

add_executable(privedit_gui WIN32
    ${PRIVEDIT_SOURCES}
    ${PRIVEDIT_HEADERS}
)

# Include dirs straight from pkg-config (src/ for our own headers).
target_include_directories(privedit_gui PRIVATE
    src
    ${SODIUM_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIRS}
)

# ---------------------------------------------------------------------------
#  Compile definitions & options
# ---------------------------------------------------------------------------
target_compile_definitions(privedit_gui PRIVATE
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0601
    WINVER=0x0601
    SODIUM_STATIC
)

target_compile_options(privedit_gui PRIVATE
    -Wall
    -Wextra
    -municode
    $<$<BOOL:${PRIVEDIT_LTO}>:-flto>
)

# ---------------------------------------------------------------------------
#  Link options
# ---------------------------------------------------------------------------
target_link_options(privedit_gui PRIVATE
    -municode
    -static
    $<$<BOOL:${PRIVEDIT_LTO}>:-flto>
)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(privedit_gui PRIVATE
        -static-libgcc
        -static-libstdc++
    )
endif()

if(PRIVEDIT_HARDENING)
    target_link_options(privedit_gui PRIVATE
        -Wl,--nxcompat
        -Wl,--dynamicbase
        -Wl,--high-entropy-va
    )
endif()

# ---------------------------------------------------------------------------
#  Link libraries
#
#  Static archives are named by absolute path. System DLLs are imported
#  the usual way -- Windows always provides them.
# ---------------------------------------------------------------------------
target_link_libraries(privedit_gui PRIVATE
    ${SODIUM_STATIC_LIB}
    ${ZLIB_STATIC_LIB}
    comctl32
    comdlg32
    shell32
    shlwapi
    gdi32
    user32
    advapi32
    ole32
    ws2_32
)

# ---------------------------------------------------------------------------
#  Resource compilation
# ---------------------------------------------------------------------------
set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/src")

# ---------------------------------------------------------------------------
#  Strip (Release only)
#
#  Prefer llvm-strip over GNU strip: on CLANGARM64 the plain `strip` is
#  the MSYS2 x86_64 binutils build, which does not understand ARM64 PE.
# ---------------------------------------------------------------------------
if(PRIVEDIT_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
    find_program(PRIVEDIT_STRIP_BIN NAMES llvm-strip strip)
    if(PRIVEDIT_STRIP_BIN)
        add_custom_command(TARGET privedit_gui POST_BUILD
            COMMAND "${PRIVEDIT_STRIP_BIN}" $<TARGET_FILE:privedit_gui>
            COMMENT "Stripping privedit_gui.exe")
    endif()
endif()

# ---------------------------------------------------------------------------
#  Summary
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "PrivEdit configuration:")
message(STATUS "  Generator      : ${CMAKE_GENERATOR}")
message(STATUS "  Build type     : ${CMAKE_BUILD_TYPE}")
message(STATUS "  CXX compiler   : ${CMAKE_CXX_COMPILER}")
message(STATUS "  RC compiler    : ${CMAKE_RC_COMPILER}")
message(STATUS "  LTO            : ${PRIVEDIT_LTO}")
message(STATUS "  Strip          : ${PRIVEDIT_STRIP}")
message(STATUS "  Hardening      : ${PRIVEDIT_HARDENING}")
message(STATUS "")