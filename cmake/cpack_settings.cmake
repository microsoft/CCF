# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

include(InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_NAME "ccf")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Confidential Consortium Framework")
set(CPACK_PACKAGE_CONTACT "https://github.com/Microsoft/CCF")
set(CPACK_RESOURCE_FILE_LICENSE "${CCF_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${CCF_RELEASE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

# CPack variables for Debian packages
set(CPACK_DEBIAN_PACKAGE_DEPENDS
    "open-enclave (>=0.13.0), libuv1 (>= 1.18.0), libc++1-8, libc++abi1-8"
)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

include(CPack)
