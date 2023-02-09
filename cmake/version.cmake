# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

unset(CCF_VERSION)
unset(CCF_RELEASE_VERSION)
unset(CCF_VERSION_SUFFIX)

option(UNSAFE_VERSION "Produce build with unsafe logging levels" OFF)

set(CCF_PROJECT "ccf_${COMPILE_TARGET}")
if(UNSAFE_VERSION)
  if(NOT ${COMPILE_TARGET} STREQUAL "sgx")
    message(
      FATAL_ERROR
        "UNSAFE_VERSION can only be set for sgx compile target (-DCOMPILE_TARGET=sgx)"
    )
  endif()
  set(CCF_PROJECT "${CCF_PROJECT}_unsafe")
  add_compile_definitions(UNSAFE_VERSION ENABLE_HISTORICAL_VERBOSE_LOGGING)
  file(WRITE ${CMAKE_BINARY_DIR}/UNSAFE "UNSAFE")
  install(FILES ${CMAKE_BINARY_DIR}/UNSAFE DESTINATION share)
endif()

# If possible, deduce project version from git environment
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
  find_package(Git)

  execute_process(
    COMMAND "bash" "-c" "${GIT_EXECUTABLE} describe --tags --match=\"ccf-*\""
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE "CCF_VERSION"
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE RETURN_CODE
  )
  if(NOT RETURN_CODE STREQUAL "0")
    message(FATAL_ERROR "Error calling git describe")
  endif()

  # Convert git description into cmake list, separated at '-'
  string(REPLACE "-" ";" CCF_VERSION_COMPONENTS ${CCF_VERSION})

  # Check that the first element equals "ccf"
  list(GET CCF_VERSION_COMPONENTS 0 FIRST)
  if(NOT FIRST STREQUAL "ccf")
    message(
      FATAL_ERROR
        "Git repository does not appear to contain any tag starting with ccf- (the repository should be cloned with sufficient depth to access the latest \"ccf-*\" tag)"
    )
  endif()
else()
  # If not in a git environment (e.g. release tarball), deduce version from the
  # source directory name
  execute_process(
    COMMAND "bash" "-c" "basename ${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE "CCF_VERSION"
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  # Convert directory name into cmake list, separated at '-'
  string(REPLACE "-" ";" CCF_VERSION_COMPONENTS ${CCF_VERSION})

  # Check that the first element equals "ccf"
  list(GET CCF_VERSION_COMPONENTS 0 FIRST)
  if(NOT FIRST STREQUAL "ccf")
    message(FATAL_ERROR "Sources directory is not in \"ccf-...\" folder")
  endif()

  message(
    STATUS "Extracting CCF version from sources directory: ${CCF_VERSION}"
  )
endif()

# Check that we have at least ccf-x.y.z
list(LENGTH CCF_VERSION_COMPONENTS CCF_VERSION_COMPONENTS_LENGTH)
if(NOT CCF_VERSION_COMPONENTS_LENGTH GREATER_EQUAL 2)
  message(FATAL_ERROR "Version does not contain expected ccf-x.y.z")
endif()

# Get the main version number
list(GET CCF_VERSION_COMPONENTS 1 CCF_RELEASE_VERSION)

# If there is any suffix, store it
if(CCF_VERSION_COMPONENTS_LENGTH GREATER 2)
  list(SUBLIST CCF_VERSION_COMPONENTS 2 -1 CCF_VERSION_SUFFIX)
  list(JOIN CCF_VERSION_SUFFIX "-" CCF_VERSION_SUFFIX)
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

file(WRITE ${CMAKE_BINARY_DIR}/VERSION_LONG "${CCF_VERSION}")
install(FILES ${CMAKE_BINARY_DIR}/VERSION_LONG DESTINATION share)
