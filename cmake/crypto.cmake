# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# EverCrypt

set(EVERCRYPT_PREFIX
    ${CCF_DIR}/3rdparty/hacl-star/evercrypt
    CACHE PATH "Prefix to the EverCrypt library"
)
message(STATUS "Using EverCrypt at ${EVERCRYPT_PREFIX}")

set(EVERCRYPT_INC ${EVERCRYPT_PREFIX} ${EVERCRYPT_PREFIX}/kremlin
                  ${EVERCRYPT_PREFIX}/kremlin/kremlib
)

file(GLOB_RECURSE EVERCRYPT_SRC "${EVERCRYPT_PREFIX}/*.[cS]")

# We need two versions of EverCrypt, because it depends on libc

if("sgx" IN_LIST COMPILE_TARGETS)
  add_library(evercrypt.enclave STATIC ${EVERCRYPT_SRC})
  target_compile_options(
    evercrypt.enclave PRIVATE -Wno-implicit-function-declaration
                              -Wno-return-type
  )
  target_compile_definitions(
    evercrypt.enclave PRIVATE INSIDE_ENCLAVE KRML_HOST_PRINTF=oe_printf
                              KRML_HOST_EXIT=oe_abort
  )
  target_link_libraries(evercrypt.enclave PRIVATE openenclave::oelibc)
  set_property(TARGET evercrypt.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(evercrypt.enclave PRIVATE ${EVERCRYPT_INC})
  install(
    TARGETS evercrypt.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

add_library(evercrypt.host STATIC ${EVERCRYPT_SRC})
set_property(TARGET evercrypt.host PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(evercrypt.host PRIVATE ${EVERCRYPT_INC})
install(
  TARGETS evercrypt.host
  EXPORT ccf
  DESTINATION lib
)

# CCFCrypto, again two versions.

set(CCFCRYPTO_SRC ${CCF_DIR}/src/crypto/hash.cpp
                  ${CCF_DIR}/src/crypto/symmetric_key.cpp
)

set(CCFCRYPTO_INC ${CCF_DIR}/src/crypto/ ${EVERCRYPT_INC})

if("sgx" IN_LIST COMPILE_TARGETS)
  add_library(ccfcrypto.enclave STATIC ${CCFCRYPTO_SRC})
  target_compile_definitions(
    ccfcrypto.enclave PRIVATE INSIDE_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD
  )
  target_compile_options(ccfcrypto.enclave PRIVATE -nostdinc++)
  target_include_directories(ccfcrypto.enclave PRIVATE ${EVERCRYPT_INC})
  target_link_libraries(
    ccfcrypto.enclave
    PRIVATE -nostdlib -nodefaultlibs -nostartfiles -Wl,--no-undefined
            -Wl,-Bstatic,-Bsymbolic,--export-dynamic,-pie evercrypt.enclave
  )
  use_oe_mbedtls(ccfcrypto.enclave)
  set_property(TARGET ccfcrypto.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)

  install(
    TARGETS ccfcrypto.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

add_library(ccfcrypto.host STATIC ${CCFCRYPTO_SRC})
target_compile_definitions(ccfcrypto.host PRIVATE)
target_compile_options(ccfcrypto.host PRIVATE -stdlib=libc++)
target_include_directories(ccfcrypto.host PRIVATE ${EVERCRYPT_INC})
target_link_libraries(ccfcrypto.host PRIVATE evercrypt.host)
use_client_mbedtls(ccfcrypto.host)
set_property(TARGET ccfcrypto.host PROPERTY POSITION_INDEPENDENT_CODE ON)

install(
  TARGETS ccfcrypto.host
  EXPORT ccf
  DESTINATION lib
)
