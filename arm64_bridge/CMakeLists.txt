cmake_minimum_required(VERSION 3.22)
project(arm32_bridge LANGUAGES C CXX)

# Pass -DBRIDGE_TARGET=<name> to match the game's System.loadLibrary() call.
set(BRIDGE_TARGET arm32_bridge CACHE STRING "Bridge library target name")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(MC4_ENABLE_NATIVE_LOGGING "Enable host and guest diagnostic logging" OFF)

# Hot JNI boolean-result probes are opt-in: the default release bridge must
# not lock/update diagnostic maps from the render-thread JNI callback path.
option(MC4_ENABLE_JNI_BOOLEAN_PROBE "Log JNI boolean results and context switches" OFF)

# Restore the historical max-quality override only in an explicitly requested
# diagnostic build; ordinary/release APKs leave guest quality selection alone.
option(MC4_ENABLE_MAX_QUALITY_DIAGNOSTIC "Apply legacy max-quality guest fields for A/B diagnostics" OFF)

include(FetchContent)

# Size: applied before FetchContent so dynarmic/fmt/mcl inherit them. Only
# JNI_OnLoad has to be exported (everything else is registered at runtime), so
# hiding the rest drops the dynsym table and most of .rela.
add_compile_options(-fvisibility=hidden -fvisibility-inlines-hidden
                    -ffunction-sections -fdata-sections)
add_link_options(-Wl,--gc-sections -Wl,--icf=all -Wl,--exclude-libs,ALL)

# Only headers are needed; keep the pinned release outside the source tree.
FetchContent_Declare(
    boost
    URL https://archives.boost.io/release/1.83.0/source/boost_1_83_0.tar.bz2
    URL_HASH SHA256=6478edfe2f3305127cffe8caf73ea0176c53769f4bf1585be237eb30798c3b8e
)
FetchContent_GetProperties(boost)
if(NOT boost_POPULATED)
    FetchContent_Populate(boost)
endif()
if(NOT EXISTS "${boost_SOURCE_DIR}/boost/version.hpp")
    message(FATAL_ERROR "Missing Boost headers; supply FETCHCONTENT_SOURCE_DIR_BOOST or allow the pinned download")
endif()
file(STRINGS "${boost_SOURCE_DIR}/boost/version.hpp" BOOST_VERSION_LINE REGEX "^#define BOOST_VERSION ")
if(NOT BOOST_VERSION_LINE STREQUAL "#define BOOST_VERSION 108300")
    message(FATAL_ERROR "Boost 1.83.0 is required")
endif()
set(BOOST_ROOT "${boost_SOURCE_DIR}")
set(BOOST_INCLUDEDIR "${boost_SOURCE_DIR}")
set(Boost_INCLUDE_DIR "${boost_SOURCE_DIR}")
set(Boost_NO_SYSTEM_PATHS ON)
set(Boost_FOUND TRUE)
include_directories("${boost_SOURCE_DIR}")

# Configure Dynarmic.
# NOTE: the real option is DYNARMIC_FRONTENDS (a list), not DYNARMIC_ENABLE_A32/A64 --
# the old names were silently ignored, so A64 was being built too.
set(DYNARMIC_FRONTENDS "A32" CACHE STRING "" FORCE)
set(DYNARMIC_TESTS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "" FORCE)  # cross-compiling: never pick up host libs

message(STATUS "Configuring pinned Dynarmic dependency...")
FetchContent_Declare(
    dynarmic
    GIT_REPOSITORY https://github.com/azahar-emu/dynarmic.git
    GIT_TAG        e77b1ba0b7da7cbe93021b01a663acfe7c4dd516
)
FetchContent_MakeAvailable(dynarmic)

# Apply the same release log policy without changing the pinned dependency.
target_compile_options(dynarmic PRIVATE
    -include "${CMAKE_CURRENT_SOURCE_DIR}/src/release_logging.h"
)
target_compile_definitions(dynarmic PRIVATE
    MC4_ENABLE_NATIVE_LOGGING=$<BOOL:${MC4_ENABLE_NATIVE_LOGGING}>
)

set(BRIDGE_SOURCES
    src/elf_loader.cpp
    src/dynarmic_host.cpp
    src/thunk_manager.cpp
    src/thunks_gl.cpp
    src/thunks_gl_gles2_core.cpp
    src/thunks_libc.cpp
    src/fast_malloc.cpp
    src/thunks_opensles.cpp   # MC4 audio is OpenSL ES direct: keeps slCreateEngine thunks
    src/jni_fake_env.cpp
    src/jni_bridge.cpp
    src/mc4_phase3.cpp        # host port of work/phase3_vfs/phase3_vfs.c
    src/mc4_graphics.cpp      # native graphics controls, applied at next launch
    src/mc4_cheats.cpp        # host port of work/offline_cheats/offline_cheats.c
)

add_library(${BRIDGE_TARGET} SHARED ${BRIDGE_SOURCES})

target_compile_options(${BRIDGE_TARGET} PRIVATE
    -include "${CMAKE_CURRENT_SOURCE_DIR}/src/release_logging.h"
)

target_include_directories(${BRIDGE_TARGET} PRIVATE
    src
    ${dynarmic_SOURCE_DIR}/include
    ${boost_SOURCE_DIR}
)

target_link_libraries(${BRIDGE_TARGET} PRIVATE
    dynarmic
    GLESv2
    GLESv3
    EGL
    OpenSLES
    log
    android
    m
    z
)

target_compile_definitions(${BRIDGE_TARGET} PRIVATE
    ANDROID
    __ANDROID__
    MC4_ENABLE_NATIVE_LOGGING=$<BOOL:${MC4_ENABLE_NATIVE_LOGGING}>
    MC4_ENABLE_JNI_BOOLEAN_PROBE=$<BOOL:${MC4_ENABLE_JNI_BOOLEAN_PROBE}>
    MC4_ENABLE_MAX_QUALITY_DIAGNOSTIC=$<BOOL:${MC4_ENABLE_MAX_QUALITY_DIAGNOSTIC}>
)

# Android 15+ devices boot with 16 KB pages; a 4 KB-aligned LOAD segment trips
# the "app isn't 16 KB compatible" loader warning.
target_link_options(${BRIDGE_TARGET} PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
    "-Wl,-z,relro"
    "-Wl,-z,now"
)

# Component test of the same active thunk/host sources used by the APK. Keep
# this opt-in: the release shared library and its link configuration do not
# change when BRIDGE_BUILD_TESTS is disabled.
option(BRIDGE_BUILD_TESTS "Build Android arm64 bridge component tests" OFF)
if(BRIDGE_BUILD_TESTS)
    add_executable(mc4_threading_contract
        tests/threading_active_contract.cpp
        ${BRIDGE_SOURCES}
    )
    target_include_directories(mc4_threading_contract PRIVATE
        src
        ${dynarmic_SOURCE_DIR}/include
        ${boost_SOURCE_DIR}
    )
    target_link_libraries(mc4_threading_contract PRIVATE
        dynarmic GLESv2 GLESv3 EGL OpenSLES log android m z
    )
    target_compile_definitions(mc4_threading_contract PRIVATE
        ANDROID __ANDROID__
        MC4_ENABLE_JNI_BOOLEAN_PROBE=$<BOOL:${MC4_ENABLE_JNI_BOOLEAN_PROBE}>
        MC4_ENABLE_MAX_QUALITY_DIAGNOSTIC=$<BOOL:${MC4_ENABLE_MAX_QUALITY_DIAGNOSTIC}>
    )
    target_link_options(mc4_threading_contract PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,-z,common-page-size=16384"
    )
endif()
