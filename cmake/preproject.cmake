# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Note: this needs to be done before project(), otherwise CMAKE_*_COMPILER is already set by CMake
# If the user has not expressed any choice, we attempt to default to Clang >= 7
# If they have expressed even a partial choice, the usual CMake selection logic applies
# If we cannot find both a suitable clang and a suitable clang++, the usual CMake selection logic applies
if ((NOT CMAKE_C_COMPILER) AND (NOT CMAKE_CXX_COMPILER)
    AND "$ENV{CC}" STREQUAL "" AND "$ENV{CXX}" STREQUAL "")
  find_program(FOUND_CMAKE_C_COMPILER NAMES clang-7.0 clang-7 clang-8)
  find_program(FOUND_CMAKE_CXX_COMPILER NAMES clang++-7.0 clang++-7 clang++-8)
  if (NOT (FOUND_CMAKE_C_COMPILER AND FOUND_CMAKE_CXX_COMPILER))
    message(WARNING "Clang >= 7 not found, will use default compiler. "
      "Override the compiler by setting CC and CXX environment variables.")
  else()
    # CMAKE_*_COMPILER can only be set once, and cannot be unset, we either
    # want both, or none at all.
    set(CMAKE_C_COMPILER "${FOUND_CMAKE_C_COMPILER}")
    set(CMAKE_CXX_COMPILER "${FOUND_CMAKE_CXX_COMPILER}")
  endif()
endif()

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    if (CMAKE_C_COMPILER_VERSION VERSION_LESS 7)
        message(WARNING "CCF officially supports Clang >= 7 only, "
            "but your Clang version (${CMAKE_C_COMPILER_VERSION}) "
            "is older than that. Build problems may occur.")
    endif()
endif()

set(CMAKE_CXX_STANDARD 17)
