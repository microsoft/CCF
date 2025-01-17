# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Note: this needs to be done before project(), otherwise CMAKE_*_COMPILER is
# already set by CMake. If the user has not expressed any choice, we attempt to
# default to Clang >= 11. If they have expressed even a partial choice, the
# usual CMake selection logic applies. If we cannot find both a suitable clang
# and a suitable clang++, the usual CMake selection logic applies
if((NOT CMAKE_C_COMPILER)
   AND (NOT CMAKE_CXX_COMPILER)
   AND "$ENV{CC}" STREQUAL ""
   AND "$ENV{CXX}" STREQUAL ""
)
  find_program(FOUND_CMAKE_C_COMPILER NAMES clang-15)
  find_program(FOUND_CMAKE_CXX_COMPILER NAMES clang++-15)
  if(NOT (FOUND_CMAKE_C_COMPILER AND FOUND_CMAKE_CXX_COMPILER))
    message(
      WARNING
        "Clang 11 or Clang 15 not found, will use default compiler. "
        "Override the compiler by setting CC and CXX environment variables."
    )
  else()
    # CMAKE_*_COMPILER can only be set once, and cannot be unset, we either want
    # both, or none at all.
    set(CMAKE_C_COMPILER "${FOUND_CMAKE_C_COMPILER}")
    set(CMAKE_CXX_COMPILER "${FOUND_CMAKE_CXX_COMPILER}")
  endif()
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  if(CMAKE_C_COMPILER_VERSION VERSION_LESS 11)
    message(WARNING "CCF officially supports Clang >= 11 only, "
                    "but your Clang version (${CMAKE_C_COMPILER_VERSION}) "
                    "is older than that. Build problems may occur."
    )
  endif()
endif()

# Build Release by default, with debug info
set(default_build_type "RelWithDebInfo")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(
    STATUS
      "Setting build type to '${default_build_type}' as none was specified."
  )
  set(CMAKE_BUILD_TYPE
      "${default_build_type}"
      CACHE STRING "Choose the type of build." FORCE
  )
  set_property(
    CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel"
                                    "RelWithDebInfo"
  )
endif()

option(TSAN "Enable Thread Sanitizers" OFF)

option(COLORED_OUTPUT "Always produce ANSI-colored output." ON)

if(${COLORED_OUTPUT})
  add_compile_options(-fcolor-diagnostics)
endif()

function(add_warning_checks name)
  target_compile_options(
    ${name}
    PRIVATE -Wall
            -Wextra
            -Werror
            -Wundef
            -Wpedantic
            -Wno-unused
            -Wno-unused-parameter
            -Wshadow
  )
endfunction()

set(SPECTRE_MITIGATION_FLAGS -mllvm -x86-speculative-load-hardening)
if("${COMPILE_TARGET}" STREQUAL "snp")
  if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_compile_options(${SPECTRE_MITIGATION_FLAGS})
  endif()
endif()

if("${COMPILE_TARGET}" STREQUAL "snp" OR "${COMPILE_TARGET}" STREQUAL "virtual")
  if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" AND NOT TSAN)
    add_compile_options(-flto)
  endif()
  # Unconditionally make linker aware of possible LTO happening. Otherwise
  # targets built in Debug and linked against this will fail linkage.
  add_link_options(-flto)
endif()

set(CMAKE_CXX_STANDARD 20)

if(USE_LIBCXX)
  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_compile_options(-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG)
  elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    add_compile_options(-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST)
  endif()
endif()
