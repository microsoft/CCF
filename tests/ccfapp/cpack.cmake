# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

include(${CCF_DIR}/cmake/cpack_ccfapp.cmake)

set(CPACK_RPM_PACKAGE_REQUIRES "${CPACK_CCF_RUNTIME_REQUIRES}")

message(STATUS "Requires: ${CPACK_RPM_PACKAGE_REQUIRES}")

set(CPACK_RPM_FILE_NAME "ccfapp")
set(CPACK_PACKAGING_INSTALL_PREFIX "/opt/ccfapp")

include(CPack)
