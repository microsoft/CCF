# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CPACK_PACKAGE_NAME "${CCF_PROJECT}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Confidential Consortium Framework")
set(CPACK_PACKAGE_CONTACT "https://github.com/Microsoft/CCF")
set(CPACK_RESOURCE_FILE_LICENSE "${CCF_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${CCF_RELEASE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

set(CPACK_DEBIAN_PACKAGE_VERSION "${CCF_RELEASE_VERSION}")

if(CCF_VERSION_SUFFIX)
  set(CPACK_DEBIAN_PACKAGE_VERSION
      "${CPACK_DEBIAN_PACKAGE_VERSION}~${CCF_VERSION_SUFFIX}"
  )
endif()

message(STATUS "Debian package version: ${CPACK_DEBIAN_PACKAGE_VERSION}")

set(CCF_DEB_BASE_DEPENDENCIES
    "libuv1 (>= 1.34.2);libc++1-10;libc++abi1-10;openssl (>=1.1.1)"
)
set(CCF_DEB_DEPENDENCIES ${CCF_DEB_BASE_DEPENDENCIES})

set(OE_VERSION "0.18.4")
if(COMPILE_TARGET STREQUAL "sgx")
  list(APPEND CCF_DEB_DEPENDENCIES "open-enclave (>=${OE_VERSION})")
else()
  list(
    APPEND CCF_DEB_DEPENDENCIES
    "open-enclave-hostverify (>=${OE_VERSION}) | open-enclave (>=${OE_VERSION})"
  )
endif()

list(JOIN CCF_DEB_DEPENDENCIES ", " CPACK_DEBIAN_PACKAGE_DEPENDS)

set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

include(CPack)
