# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Note: this needs to be done before project(), otherwise CMAKE_*_COMPILER is
# already set by CMake. If the user has not expressed any choice, we attempt to
# set a default Clang choice. If they have expressed even a partial choice, the
# usual CMake selection logic applies. If we cannot find both a suitable clang
# and a suitable clang++, the usual CMake selection logic applies
if((NOT CMAKE_C_COMPILER)
   AND (NOT CMAKE_CXX_COMPILER)
   AND "$ENV{CC}" STREQUAL ""
   AND "$ENV{CXX}" STREQUAL ""
)
  find_program(FOUND_CMAKE_C_COMPILER NAMES clang)
  find_program(FOUND_CMAKE_CXX_COMPILER NAMES clang++)

  # vvvvv Ubuntu-20.04, to be removed after support dropped. vvvvv #
  if(NOT (FOUND_CMAKE_C_COMPILER AND FOUND_CMAKE_CXX_COMPILER))
    find_program(FOUND_CMAKE_C_COMPILER NAMES clang-15)
    find_program(FOUND_CMAKE_CXX_COMPILER NAMES clang++-15)
  endif()
  # ^^^^^ Ubuntu-20.04, to be removed after support dropped. ^^^^^ #

  if(NOT (FOUND_CMAKE_C_COMPILER AND FOUND_CMAKE_CXX_COMPILER))
    message(
      WARNING
        "Clang not found, will use default compiler. "
        "Override the compiler by setting CC and CXX environment variables."
    )
  else()
    # CMAKE_*_COMPILER can only be set once, and cannot be unset, we either want
    # both, or none at all.
    set(CMAKE_C_COMPILER "${FOUND_CMAKE_C_COMPILER}")
    set(CMAKE_CXX_COMPILER "${FOUND_CMAKE_CXX_COMPILER}")
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
            -Wno-unused-parameter
            -Wno-unused-function
            -Wshadow
  )
endfunction()

set(CMAKE_CXX_STANDARD 20)
