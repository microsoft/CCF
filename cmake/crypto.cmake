# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# EverCrypt

set(EVERCRYPT_PREFIX ${CCF_DIR}/3rdparty/evercrypt CACHE PATH "Prefix to the EverCrypt library")
message(STATUS "Using EverCrypt at ${EVERCRYPT_PREFIX}")

set(EVERCRYPT_INC
  ${EVERCRYPT_PREFIX}
  ${EVERCRYPT_PREFIX}/kremlin/include
)

file(GLOB_RECURSE EVERCRYPT_SRC "${EVERCRYPT_PREFIX}/*.[cS]")

file(GLOB EVERCRYPT_SRC_EXCEPT PRIVATE
  # Use this with MSVC (unverified, optimized)
  "${EVERCRYPT_PREFIX}/kremlin/kremlib/fstar_uint128_msvc.c")
list(REMOVE_ITEM EVERCRYPT_SRC ${EVERCRYPT_SRC_EXCEPT})


# We need two versions of EverCrypt, because it depends on libc

add_library(evercrypt.enclave STATIC ${EVERCRYPT_SRC})
target_compile_options(evercrypt.enclave PRIVATE -nostdinc -U__linux__ -Wno-everything)
# TODO(#important|#pbft): Find out why kremlin needs this only when PBFT is on (KRML_HOST_PRINTF)
target_compile_definitions(evercrypt.enclave PRIVATE INSIDE_ENCLAVE KRML_HOST_PRINTF=oe_printf)
target_include_directories(evercrypt.enclave SYSTEM PRIVATE ${OE_LIBC_INCLUDE_DIR})
set_property(TARGET evercrypt.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(evercrypt.enclave PRIVATE ${EVERCRYPT_INC})

add_library(evercrypt.host STATIC ${EVERCRYPT_SRC})
target_compile_options(evercrypt.host PRIVATE -Wno-everything)
set_property(TARGET evercrypt.host PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(evercrypt.host PRIVATE ${EVERCRYPT_INC})


# Merkle Tree Library

set(MERKLE_TREE_PREFIX ${CCF_DIR}/3rdparty/merkle_tree)
file(GLOB MERKLE_TREE_SRC "${MERKLE_TREE_PREFIX}/*.[c]")

add_library(merkle_tree.enclave ${MERKLE_TREE_SRC})
target_compile_options(merkle_tree.enclave PRIVATE -nostdinc -U__linux__ -Wno-everything)
target_compile_definitions(merkle_tree.enclave PRIVATE INSIDE_ENCLAVE)
target_include_directories(merkle_tree.enclave PRIVATE ${EVERCRYPT_INC})
target_include_directories(merkle_tree.enclave SYSTEM PRIVATE ${OE_LIBC_INCLUDE_DIR})
target_link_libraries(merkle_tree.enclave PRIVATE evercrypt.enclave)
set_property(TARGET merkle_tree.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
set(MERKLE_TREE_INC ${MERKLE_TREE_PREFIX} ${EVERCRYPT_INC})

add_library(merkle_tree.host ${MERKLE_TREE_SRC})
target_compile_options(merkle_tree.host PRIVATE -Wno-everything)
target_include_directories(merkle_tree.host PRIVATE ${EVERCRYPT_INC})
target_link_libraries(merkle_tree.host PRIVATE evercrypt.host)
set_property(TARGET merkle_tree.host PROPERTY POSITION_INDEPENDENT_CODE ON)
set(MERKLE_TREE_INC ${MERKLE_TREE_PREFIX} ${EVERCRYPT_INC})


# CCFCrypto, again two versions.

set(CCFCRYPTO_SRC
  ${CCF_DIR}/src/crypto/hash.cpp
  ${CCF_DIR}/src/crypto/symmkey.cpp
)

set(CCFCRYPTO_INC ${CCF_DIR}/src/crypto/ ${EVERCRYPT_INC})

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

add_library(ccfcrypto.host STATIC
  ${CCFCRYPTO_SRC})
target_compile_definitions(ccfcrypto.host PRIVATE )
target_compile_options(ccfcrypto.host PRIVATE )
target_include_directories(ccfcrypto.host PRIVATE ${EVERCRYPT_INC})
target_link_libraries(ccfcrypto.host PRIVATE evercrypt.host)
use_client_mbedtls(ccfcrypto.host)
set_property(TARGET ccfcrypto.host PROPERTY POSITION_INDEPENDENT_CODE ON)
