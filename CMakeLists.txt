cmake_minimum_required(VERSION 3.20)

# Default to Release for single-config generators (MinGW Makefiles, Make,
# Ninja). Without this we end up with debug-ish binaries 2-3x the legacy
# size. Multi-config generators (Visual Studio, Xcode) pick at build time.
get_property(IS_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT IS_MULTI_CONFIG AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

project(luadch
    VERSION 3.2.0
    DESCRIPTION "luadch — DC++ ADC hub server"
    LANGUAGES C CXX
)

# Strip symbols on Release builds with GCC/Clang link, matching the legacy
# `strip --strip-unneeded` step from compile / compile_with_mingw.bat.
# Without this our Release binaries are 2-3x the legacy size on disk.
# MSVC does not understand -s; PDB stripping is a different mechanism.
if(NOT MSVC AND CMAKE_BUILD_TYPE STREQUAL "Release")
    add_link_options(-s)
endif()

# -----------------------------------------------------------------------------
# Default install layout: build/install/luadch — keeps the source tree clean
# and matches the historical build_*/luadch/ layout from the legacy scripts.
# Override with -DCMAKE_INSTALL_PREFIX=... if needed.
# -----------------------------------------------------------------------------
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install/luadch"
        CACHE PATH "luadch install root" FORCE)
endif()

# -----------------------------------------------------------------------------
# RPATH: on ELF platforms the hub binary needs to find liblua.so / *.so
# plugins as siblings (the install layout puts liblua.so next to the binary
# and the plugins under lib/<name>/<name>.so).
# -----------------------------------------------------------------------------
if(UNIX AND NOT APPLE)
    set(CMAKE_INSTALL_RPATH "$ORIGIN")
    set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
endif()

# Position-Independent Code for everything (required for shared libs)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# -----------------------------------------------------------------------------
# OpenSSL: used by luasec, adclib (AES-GCM via EVP_CIPHER, RAND_bytes).
# find_package finds the system install on Linux; on Windows pass
# -DOPENSSL_ROOT_DIR=C:/OpenSSL.
#
# Phase 7g F-DEP-4: pin OpenSSL >= 3.0 so the build fails loudly if a
# maintainer somehow links against the EOL'd 1.1.1 series (EOL
# 2023-09-11). The Windows install path already ships libssl-3-x64.dll
# / libcrypto-3-x64.dll, so 3.x has been the documented runtime; this
# just makes the Linux build match.
# -----------------------------------------------------------------------------
find_package(OpenSSL 3.0 REQUIRED)
message(STATUS "luadch: OpenSSL ${OPENSSL_VERSION} at ${OPENSSL_INCLUDE_DIR}")

# -----------------------------------------------------------------------------
# zlib: Phase 8 S4b (ADC-EXT ZLIF stream compression). Used by the
# zlib_stream C module that wraps deflate / inflate streams with the
# Z_SYNC_FLUSH semantic ADC mandates. This is the one dependency that is
# NOT bundled - it must come from the build environment.
#
# EVERY build path must install the zlib DEVELOPMENT package explicitly;
# there is no environment where it can be assumed present. The runtime
# library (libz.so.1) is on virtually every Linux box because half of
# userspace links it, but the headers and the libz.so link ship only in
# zlib1g-dev, and build-essential does NOT depend on it - so this
# find_package fails on an otherwise complete toolchain. An earlier
# version of this comment claimed the aarch64 Bullseye container had zlib
# "as a base-system package - no change needed"; that was wrong and left
# all three release.yml legs without it (never noticed, because the
# release workflow only fires on v* tags and the 3.1.x line predates
# zlib_stream). Install sites, keep in sync:
#   .github/workflows/release.yml  - zlib1g-dev (x2), mingw-w64-ucrt-x86_64-zlib
#   .github/workflows/smoke.yml    - zlib1g-dev, mingw-w64-ucrt-x86_64-zlib
#   docker/Dockerfile              - zlib-dev (alpine)
# Building from source? See docs/BUILDING.md.
# -----------------------------------------------------------------------------
find_package(ZLIB REQUIRED)
message(STATUS "luadch: ZLIB ${ZLIB_VERSION_STRING} at ${ZLIB_INCLUDE_DIRS}")

# -----------------------------------------------------------------------------
# Modules (each builds the artefacts listed in docs/phases/PHASE_1.md §3)
# -----------------------------------------------------------------------------
add_subdirectory(lua/src)
add_subdirectory(adclib)
add_subdirectory(luasocket)
add_subdirectory(luasec)
add_subdirectory(zlib_stream)
add_subdirectory(hub)

# -----------------------------------------------------------------------------
# Pure-Lua and runtime tree installs. These are flat copies; matches the
# legacy compile/compile_with_mingw.bat behaviour 1:1.
# -----------------------------------------------------------------------------

# Lua-side helpers
install(FILES slnunicode/unicode.lua DESTINATION lib/unicode)
install(FILES basexx/basexx.lua      DESTINATION lib/basexx)
install(FILES slaxml/slaxml.lua      DESTINATION lib/slaxml)
install(FILES dkjson/dkjson.lua      DESTINATION lib/dkjson)

# Bundled Mozilla CA root certificates (Precursor 0d of #78 arc).
# Source-of-truth install: NOT under examples/, so Docker volume-
# mounts on host ./certs/ do NOT overlay this file. cacert_bootstrap
# copies it to certs/ca-bundle.pem on first boot when missing or
# (with cfg ca_bundle_auto_update=true) when the runtime copy is
# out of date. See docs/CACERT.md.
install(FILES examples/certs/ca-bundle.pem DESTINATION lib/luadch)

# Runtime trees
# #445: exclude the legacy core/hci.lua from the install. It is the
# migration source for hub_runtime's runtime counter, which moved to
# scripts/data/hub_runtime.tbl. If the install shipped/overwrote it, a
# `cmake --install` over an existing tree would zero the operator's
# on-disk core/hci.lua BEFORE the hub boots and the migration can read it
# - defeating the migration. Excluding it leaves the operator's value in
# place long enough to be adopted. A future release removes core/hci.lua.
install(DIRECTORY core/        DESTINATION core PATTERN "hci.lua" EXCLUDE)
install(DIRECTORY scripts/     DESTINATION scripts)
install(DIRECTORY examples/cfg/   DESTINATION cfg)
install(DIRECTORY examples/certs/ DESTINATION certs)
install(DIRECTORY lang/           DESTINATION lang)
install(DIRECTORY docs/        DESTINATION docs)

# Empty log dir (the hub writes its log files here at runtime)
install(DIRECTORY DESTINATION log)

# -----------------------------------------------------------------------------
# Windows: bundle OpenSSL DLLs at install root so the hub can load them
# without OPENSSL_ROOT_DIR being on PATH at runtime.
# -----------------------------------------------------------------------------
if(WIN32)
    if(NOT DEFINED OPENSSL_ROOT_DIR)
        message(FATAL_ERROR
            "OPENSSL_ROOT_DIR must be set on Windows so we can install "
            "libssl-3-x64.dll and libcrypto-3-x64.dll alongside Luadch.exe. "
            "Pass -DOPENSSL_ROOT_DIR=C:/OpenSSL on the cmake command line."
        )
    endif()
    # Search both flat (WinLibs / ShiningLight: DLLs at OPENSSL_ROOT_DIR root)
    # and standard (msys2 UCRT64: DLLs under bin/) layouts so the same build
    # recipe works in both environments.
    foreach(_dll libssl-3-x64.dll libcrypto-3-x64.dll)
        string(MAKE_C_IDENTIFIER "${_dll}" _dll_var)
        find_file(_openssl_${_dll_var}
            NAMES ${_dll}
            HINTS "${OPENSSL_ROOT_DIR}" "${OPENSSL_ROOT_DIR}/bin"
            NO_DEFAULT_PATH
            REQUIRED
        )
        install(FILES "${_openssl_${_dll_var}}" DESTINATION .)
        unset(_openssl_${_dll_var} CACHE)
    endforeach()
endif()
