# ===========================================================================
#  PrivEdit GUI -- CMake build for MinGW-w64 (Windows 7 - 11)
#
#  Dependencies (all static, all from MSYS2 MinGW64):
#     libsodium   -- Argon2id + XChaCha20-Poly1305
#     zlib        -- payload compression
#
#  Configure (from a PowerShell / cmd prompt):
#
#     cmake -S . -B build ^
#           -G "MinGW Makefiles" ^
#           -DCMAKE_TOOLCHAIN_FILE=cmake/mingw64-toolchain.cmake ^
#           -DCMAKE_BUILD_TYPE=Release
#
#     cmake --build build --parallel
# ===========================================================================

cmake_minimum_required(VERSION 3.20)

project(PrivEdit
        VERSION   1.0.0
        LANGUAGES CXX RC)

# ---------------------------------------------------------------------------
#  Toolchain sanity
# ---------------------------------------------------------------------------
if(NOT WIN32)
    message(FATAL_ERROR "PrivEdit GUI is Windows-only.")
endif()
if(NOT MINGW)
    message(FATAL_ERROR
        "PrivEdit must be built with MinGW-w64. Pass "
        "-DCMAKE_TOOLCHAIN_FILE=cmake/mingw64-toolchain.cmake.")
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
# ---------------------------------------------------------------------------
# zlib: from CMake's own FindZLIB.
find_package(ZLIB REQUIRED)

# libsodium: via pkg-config -- the canonical way to locate the
# MSYS2 static archive.
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# Warn loudly if zlib resolves to a shared library.
get_target_property(_zlib_type ZLIB::ZLIB TYPE)
if(_zlib_type STREQUAL "SHARED_LIBRARY")
    message(WARNING
        "ZLIB::ZLIB resolved to a SHARED library. "
        "Install mingw-w64-x86_64-zlib-static for a fully self-contained exe.")
endif()

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

target_include_directories(privedit_gui PRIVATE src)

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
#  Link options -- fully static, hardened.
# ---------------------------------------------------------------------------
target_link_options(privedit_gui PRIVATE
    -municode
    -static
    -static-libgcc
    -static-libstdc++
    $<$<BOOL:${PRIVEDIT_LTO}>:-flto>
)

if(PRIVEDIT_HARDENING)
    target_link_options(privedit_gui PRIVATE
        -Wl,--nxcompat
        -Wl,--dynamicbase
        -Wl,--high-entropy-va
    )
endif()

# ---------------------------------------------------------------------------
#  Link libraries
# ---------------------------------------------------------------------------
target_link_libraries(privedit_gui PRIVATE
    PkgConfig::SODIUM
    ZLIB::ZLIB
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
# ---------------------------------------------------------------------------
if(PRIVEDIT_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
    find_program(PRIVEDIT_STRIP_BIN strip)
    if(PRIVEDIT_STRIP_BIN)
        add_custom_command(TARGET privedit_gui POST_BUILD
            COMMAND "${PRIVEDIT_STRIP_BIN}" $<TARGET_FILE:privedit_gui>
            COMMENT "Stripping privedit_gui.exe")
    endif()
endif()

# ---------------------------------------------------------------------------
#  Informative output
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "PrivEdit configuration:")
message(STATUS "  Generator      : ${CMAKE_GENERATOR}")
message(STATUS "  Build type     : ${CMAKE_BUILD_TYPE}")
message(STATUS "  CXX compiler   : ${CMAKE_CXX_COMPILER}")
message(STATUS "  LTO            : ${PRIVEDIT_LTO}")
message(STATUS "  Strip          : ${PRIVEDIT_STRIP}")
message(STATUS "  Hardening      : ${PRIVEDIT_HARDENING}")
message(STATUS "  libsodium      : ${SODIUM_VERSION}")
message(STATUS "  zlib           : ${ZLIB_VERSION_STRING}")
message(STATUS "")