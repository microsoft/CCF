# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CPACK_PACKAGE_NAME "${CCF_PROJECT}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Confidential Consortium Framework")
set(CPACK_PACKAGE_CONTACT "https://github.com/Microsoft/CCF")
set(CPACK_RESOURCE_FILE_LICENSE "${CCF_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${CCF_RELEASE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

set(CPACK_RPM_PACKAGE_VERSION "${CCF_RELEASE_VERSION}")

if(CCF_VERSION_SUFFIX)
  set(CPACK_RPM_PACKAGE_VERSION
      "${CPACK_RPM_PACKAGE_VERSION}~${CCF_VERSION_SUFFIX}"
  )
endif()

message(STATUS "RPM package version: ${CPACK_RPM_PACKAGE_VERSION}")

set(CCF_RPM_DEPENDENCIES
    "libuv >= 1.34.2, openssl >= 3.3.0, nghttp2 >= 1.40.0, curl >= 7.68.0, libcxxabi >= 18.1.2"
)

message(STATUS "RPM package dependencies: ${CCF_RPM_DEPENDENCIES}")

set(CPACK_RPM_PACKAGE_REQUIRES "${CCF_RPM_DEPENDENCIES}")

set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

include(CPack)
