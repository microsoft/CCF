# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(SSS_PREFIX
    ${CCF_3RD_PARTY_INTERNAL_DIR}/sss
    CACHE PATH "Prefix to the Shamir Secret Sharing (sss) library"
)
message(STATUS "Using sss at ${SSS_PREFIX}")

set(SSS_SRC ${SSS_PREFIX}/sss.c ${SSS_PREFIX}/hazmat.c
            ${SSS_PREFIX}/tweetnacl.c
)

if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library_c(sss.enclave ${SSS_SRC})
  install(
    TARGETS sss.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

add_library(sss.host STATIC ${SSS_SRC})
add_san(sss.host)
set_property(TARGET sss.host PROPERTY POSITION_INDEPENDENT_CODE ON)

if(INSTALL_VIRTUAL_LIBRARIES)
  install(
    TARGETS sss.host
    EXPORT ccf
    DESTINATION lib
  )
endif()
