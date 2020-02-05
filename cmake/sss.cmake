# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(SSS_PREFIX
    ${CCF_DIR}/3rdparty/sss
    CACHE PATH "Prefix to the Shamir Secret Sharing library"
)
message(STATUS "Using SSS at ${SSS_PREFIX}")

set(SSS_SRC
    ${SSS_PREFIX}/sss.c ${SSS_PREFIX}/hazmat.c
    # ${SSS_PREFIX}/randombytes.c
    ${SSS_PREFIX}/tweetnacl.c
)

if("sgx" IN_LIST TARGET)
  add_library(sss.enclave STATIC ${SSS_SRC})
  target_include_directories(sss.enclave PRIVATE ${CCF_DIR}/src/tls)
  set_property(TARGET sss.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
  # use_oe_mbedtls(sss.enclave) # TODO: Will be required for entropy?
  install(TARGETS sss.enclave EXPORT ccf DESTINATION lib)
endif()

add_library(sss.host STATIC ${SSS_SRC})
target_include_directories(sss.host PRIVATE ${CCF_DIR}/src/tls)
set_property(TARGET sss.host PROPERTY POSITION_INDEPENDENT_CODE ON)
install(TARGETS sss.host EXPORT ccf DESTINATION lib)
# use_client_mbedtls(sss.host) # TODO: Will be required for entropy?