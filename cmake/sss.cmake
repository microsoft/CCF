# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(SSS_PREFIX
    ${CCF_DIR}/3rdparty/sss
    CACHE PATH "Prefix to the Shamir Secret Sharing (sss) library"
)
message(STATUS "Using sss at ${SSS_PREFIX}")

set(SSS_SRC ${SSS_PREFIX}/sss.c ${SSS_PREFIX}/hazmat.c
            ${SSS_PREFIX}/tweetnacl.c
)

if("sgx" IN_LIST COMPILE_TARGETS)
  add_library(sss.enclave STATIC ${SSS_SRC})
  set_property(TARGET sss.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
  install(
    TARGETS sss.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

add_library(sss.host STATIC ${SSS_SRC})
set_property(TARGET sss.host PROPERTY POSITION_INDEPENDENT_CODE ON)
install(
  TARGETS sss.host
  EXPORT ccf
  DESTINATION lib
)
