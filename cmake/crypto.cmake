# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# EverCrypt

set(EVERCRYPT_PREFIX ${CCF_DIR}/3rdparty/evercrypt CACHE PATH "Prefix to the EverCrypt library")
message(STATUS "Using EverCrypt at ${EVERCRYPT_PREFIX}")

set(EVERCRYPT_INC
  ${EVERCRYPT_PREFIX}
  ${EVERCRYPT_PREFIX}/kremlin
)

file(GLOB_RECURSE EVERCRYPT_SRC "${EVERCRYPT_PREFIX}/*.[cS]")

file(GLOB EVERCRYPT_SRC_EXCEPT PRIVATE
  # Use this with MSVC (unverified, optimized)
  "${EVERCRYPT_PREFIX}/kremlin/kremlib/fstar_uint128_msvc.c")
list(REMOVE_ITEM EVERCRYPT_SRC ${EVERCRYPT_SRC_EXCEPT})


# We need two versions of EverCrypt, because it depends on libc

if(NOT VIRTUAL_ONLY)
  add_library(evercrypt.enclave STATIC ${EVERCRYPT_SRC})
  target_compile_options(evercrypt.enclave PRIVATE -nostdinc -U__linux__ -Wno-everything)
  target_compile_definitions(evercrypt.enclave PRIVATE INSIDE_ENCLAVE KRML_HOST_PRINTF=oe_printf KRML_HOST_EXIT=oe_abort)
  target_include_directories(evercrypt.enclave SYSTEM PRIVATE ${OE_LIBC_INCLUDE_DIR})
  set_property(TARGET evercrypt.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(evercrypt.enclave PRIVATE ${EVERCRYPT_INC})
endif()

add_library(evercrypt.host STATIC ${EVERCRYPT_SRC})
target_compile_options(evercrypt.host PRIVATE -Wno-everything)
set_property(TARGET evercrypt.host PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(evercrypt.host PRIVATE ${EVERCRYPT_INC})

# CCFCrypto, again two versions.

set(CCFCRYPTO_SRC
  ${CCF_DIR}/src/crypto/hash.cpp
  ${CCF_DIR}/src/crypto/symmkey.cpp
)

set(CCFCRYPTO_INC ${CCF_DIR}/src/crypto/ ${EVERCRYPT_INC})

if(NOT VIRTUAL_ONLY)
  add_library(ccfcrypto.enclave STATIC ${CCFCRYPTO_SRC})
  target_compile_definitions(ccfcrypto.enclave PRIVATE
    INSIDE_ENCLAVE
    _LIBCPP_HAS_THREAD_API_PTHREAD
  )
  target_compile_options(ccfcrypto.enclave PRIVATE -nostdinc++ -U__linux__)
  target_include_directories(ccfcrypto.enclave PRIVATE
    ${OE_LIBCXX_INCLUDE_DIR}
    ${OE_LIBC_INCLUDE_DIR}
    ${OE_TP_INCLUDE_DIR}
    ${EVERCRYPT_INC}
  )
  target_link_libraries(ccfcrypto.enclave PRIVATE
    -nostdlib -nodefaultlibs -nostartfiles
    -Wl,--no-undefined
    -Wl,-Bstatic,-Bsymbolic,--export-dynamic,-pie
    -lgcc
    evercrypt.enclave
  )
  use_oe_mbedtls(ccfcrypto.enclave)
  set_property(TARGET ccfcrypto.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()

add_library(ccfcrypto.host STATIC
  ${CCFCRYPTO_SRC})
target_compile_definitions(ccfcrypto.host PRIVATE )
target_compile_options(ccfcrypto.host PRIVATE )
target_include_directories(ccfcrypto.host PRIVATE ${EVERCRYPT_INC})
target_link_libraries(ccfcrypto.host PRIVATE evercrypt.host)
use_client_mbedtls(ccfcrypto.host)
set_property(TARGET ccfcrypto.host PROPERTY POSITION_INDEPENDENT_CODE ON)
