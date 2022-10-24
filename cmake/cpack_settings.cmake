# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CPACK_PACKAGE_NAME ${CCF_PROJECT})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Confidential Consortium Framework")
set(CPACK_PACKAGE_CONTACT "https://github.com/Microsoft/CCF")
set(CPACK_RESOURCE_FILE_LICENSE "${CCF_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${CCF_RELEASE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

if(CCF_VERSION_SUFFIX)
  set(CPACK_DEBIAN_PACKAGE_VERSION
    "${CCF_RELEASE_VERSION}~${CCF_VERSION_SUFFIX}"
  )
  message(
    STATUS "Debian package will include suffix: ${CPACK_DEBIAN_PACKAGE_VERSION}"
  )
endif()

set(CCF_DEB_BASE_DEPENDENCIES "libuv1 (>= 1.34.2);libc++1-10;libc++abi1-10;openssl (>=1.1.1)")
set(CCF_DEB_DEPENDENCIES ${CCF_DEB_BASE_DEPENDENCIES})

if("sgx" IN_LIST COMPILE_TARGETS)
  list(APPEND CCF_DEB_DEPENDENCIES "open-enclave (>=0.18.2)")
endif()

# CPack variables for Debian packages
if("sgx" IN_LIST COMPILE_TARGETS)
  list(JOIN CCF_DEB_DEPENDENCIES ", " CPACK_DEBIAN_PACKAGE_DEPENDS)
endif()

set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

include(CPack)
