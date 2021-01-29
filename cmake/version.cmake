# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

unset(CCF_VERSION)
unset(CCF_RELEASE_VERSION)

# If possible, deduce project version from git environment
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
  find_package(Git)

  execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --tags
    OUTPUT_VARIABLE "CCF_VERSION"
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE RETURN_CODE
  )
  if (NOT RETURN_CODE STREQUAL "0")
    message(FATAL_ERROR "Git repository does not appear to contain any tag (the repository should be cloned with sufficient depth to access the latest \"ccf-*\" tag)")
  endif()
  execute_process(
    COMMAND "bash" "-c"
            "${GIT_EXECUTABLE} describe --tags --abbrev=0 | tr -d ccf-"
    OUTPUT_VARIABLE "CCF_RELEASE_VERSION"
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()

if(NOT CCF_RELEASE_VERSION)
  # If not in a git environment (e.g. release tarball), deduce version from the
  # source directory name
  execute_process(
    COMMAND "bash" "-c"
            "[[ $(basename ${CMAKE_CURRENT_SOURCE_DIR}) =~ ^CCF-.* ]]"
    RESULT_VARIABLE "IS_CCF_FOLDER"
  )

  if(NOT ${IS_CCF_FOLDER} STREQUAL "0")
    message(FATAL_ERROR "Sources directory is not in \"CCF-...\" folder")
  endif()

  execute_process(
    COMMAND "bash" "-c" "basename ${CMAKE_CURRENT_SOURCE_DIR} | cut -d'-' -f2"
    OUTPUT_VARIABLE "CCF_VERSION"
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  set(CCF_RELEASE_VERSION ${CCF_VERSION})
  message(STATUS "CCF version deduced from sources directory: ${CCF_VERSION}")
endif()

# Check that release version is semver
execute_process(
  COMMAND "bash" "-c"
          "[[ ${CCF_RELEASE_VERSION} =~ ^([[:digit:]])+(\.([[:digit:]])+)*$ ]]"
  RESULT_VARIABLE "VERSION_IS_SEMVER"
)

if(NOT ${VERSION_IS_SEMVER} STREQUAL "0")
  message(
    WARNING
      "Release version \"${CCF_RELEASE_VERSION}\" does not follow semver. Defaulting to project version 0.0.0"
  )
  set(CCF_RELEASE_VERSION "0.0.0")
endif()

file(WRITE ${CMAKE_BINARY_DIR}/VERSION "${CCF_RELEASE_VERSION}")
install(FILES ${CMAKE_BINARY_DIR}/VERSION DESTINATION share)
