# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CPACK_PACKAGE_NAME "${CCF_PROJECT}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Confidential Consortium Framework")
set(CPACK_PACKAGE_DESCRIPTION ${PROJECT_DESCRIPTION})
set(CPACK_PACKAGE_CONTACT "https://github.com/Microsoft/CCF")
set(CPACK_RESOURCE_FILE_LICENSE "${CCF_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${CCF_RELEASE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

# RPM-specific settings

set(CPACK_RPM_PACKAGE_VERSION "${CCF_RELEASE_VERSION}")

if(CCF_VERSION_SUFFIX)
  set(CPACK_RPM_PACKAGE_VERSION
      "${CPACK_RPM_PACKAGE_VERSION}~${CCF_VERSION_SUFFIX}"
  )
endif()

message(STATUS "RPM package version: ${CPACK_RPM_PACKAGE_VERSION}")

set(OPENSSL_MINIMAL_VERSION "3.3.0")
set(NGHTTP2_MINIMAL_VERSION "1.40.0")

set(CPACK_RPM_PACKAGE_LICENSE "Apache-2.0")
set(CPACK_RPM_PACKAGE_DESCRIPTION "${PROJECT_DESCRIPTION}")

if(CCF_DEVEL)
  set(CCF_RPM_BASE_DEPENDENCIES
      "openssl-devel >= ${OPENSSL_MINIMAL_VERSION}, nghttp2-devel >= ${NGHTTP2_MINIMAL_VERSION}"
  )
  # + build toolchain
  set(CCF_RPM_BASE_DEPENDENCIES
      "${CCF_RPM_BASE_DEPENDENCIES}, cmake >= 3.30, build-essential >= 3.0, clang >= 18.1.2, ninja-build >= 1.11.1"
  )
  # + alter name
  set(CPACK_PACKAGE_NAME "${CPACK_PACKAGE_NAME}_devel")
  # + alter summary
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
      "${CPACK_PACKAGE_DESCRIPTION_SUMMARY} (development)"
  )
else()
  set(CCF_RPM_BASE_DEPENDENCIES
      "openssl >= ${OPENSSL_MINIMAL_VERSION}, nghttp2 >= ${NGHTTP2_MINIMAL_VERSION}"
  )
endif()

set(CCF_RPM_DEPENDENCIES
    "${CCF_RPM_BASE_DEPENDENCIES}, libuv >= 1.34.2, curl >= 7.68.0, libcxxabi >= 18.1.2"
)

message(STATUS "RPM package dependencies: ${CCF_RPM_DEPENDENCIES}")

set(CPACK_RPM_PACKAGE_REQUIRES "${CCF_RPM_DEPENDENCIES}")

# Default is formed as `name + version + release + architecture` joined via `-`.
# To keep consistent release naming, we want - package name as  `name + version
# + architecture` - output format via underscore:
# `name_version_architecture.rpm`

# CPACK_RPM_PACKAGE_ARCHITECTURE is empty for some reason, however it should be
# set to `uname -m` output, see
# https://cmake.org/cmake/help/v3.7/module/CPackRPM.html#variable:CPACK_RPM_PACKAGE_ARCHITECTURE).
execute_process(COMMAND uname -m OUTPUT_VARIABLE CPACK_RPM_PACKAGE_ARCHITECTURE)
string(STRIP "${CPACK_RPM_PACKAGE_ARCHITECTURE}" CPACK_RPM_PACKAGE_ARCHITECTURE)

set(FINAL_PACKAGE_NAME
    "${CPACK_PACKAGE_NAME}_${CPACK_RPM_PACKAGE_VERSION}_${CPACK_RPM_PACKAGE_ARCHITECTURE}"
)

message(STATUS "Final RPM package name: ${FINAL_PACKAGE_NAME}.rpm")

set(CPACK_RPM_FILE_NAME "${FINAL_PACKAGE_NAME}")

# Reproducible builds Macros
set(CPACK_RPM_SPEC_MORE_DEFINE
    "%define _buildhost reproducible
%define use_source_date_epoch_as_buildtime Y
%define clamp_mtime_to_source_date_epoch Y
"
)

include(CPack)
