# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Note: this needs to be done before project(), otherwise CMAKE_*_COMPILER is
# already set by CMake. If the user has not expressed any choice, we attempt to
# default to Clang >= 8 If they have expressed even a partial choice, the usual
# CMake selection logic applies. If we cannot find both a suitable clang and a
# suitable clang++, the usual CMake selection logic applies
if((NOT CMAKE_C_COMPILER)
   AND (NOT CMAKE_CXX_COMPILER)
   AND "$ENV{CC}" STREQUAL ""
   AND "$ENV{CXX}" STREQUAL ""
)
  find_program(FOUND_CMAKE_C_COMPILER NAMES clang-10 clang-8)
  find_program(FOUND_CMAKE_CXX_COMPILER NAMES clang++-10 clang++-8)
  if(NOT (FOUND_CMAKE_C_COMPILER AND FOUND_CMAKE_CXX_COMPILER))
    message(
      WARNING
        "Clang >= 8 not found, will use default compiler. "
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
  if(CMAKE_C_COMPILER_VERSION VERSION_LESS 8)
    message(WARNING "CCF officially supports Clang >= 8 only, "
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

option(COLORED_OUTPUT "Always produce ANSI-colored output (Clang only)." TRUE)

if(${COLORED_OUTPUT})
  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    add_compile_options(-fcolor-diagnostics)
  endif()
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
  )
endfunction()

set(CMAKE_CXX_STANDARD 17)
