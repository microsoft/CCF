# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CCFCRYPTO_SRC
    ${CCF_DIR}/src/crypto/base64.cpp
    ${CCF_DIR}/src/crypto/entropy.cpp
    ${CCF_DIR}/src/crypto/hash.cpp
    ${CCF_DIR}/src/crypto/symmetric_key.cpp
    ${CCF_DIR}/src/crypto/key_pair.cpp
    ${CCF_DIR}/src/crypto/rsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/verifier.cpp
    ${CCF_DIR}/src/crypto/key_wrap.cpp
    ${CCF_DIR}/src/crypto/openssl/symmetric_key.cpp
    ${CCF_DIR}/src/crypto/openssl/public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/hash.cpp
    ${CCF_DIR}/src/crypto/openssl/rsa_public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/rsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/verifier.cpp
)

if("sgx" IN_LIST COMPILE_TARGETS)
  add_enclave_library(ccfcrypto.enclave ${CCFCRYPTO_SRC})

  install(
    TARGETS ccfcrypto.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

add_library(ccfcrypto.host STATIC ${CCFCRYPTO_SRC})
add_san(ccfcrypto.host)
target_compile_options(ccfcrypto.host PUBLIC ${COMPILE_LIBCXX})
target_link_options(ccfcrypto.host PUBLIC ${LINK_LIBCXX})
target_link_libraries(ccfcrypto.host PUBLIC crypto)
target_link_libraries(ccfcrypto.host PUBLIC ssl)
set_property(TARGET ccfcrypto.host PROPERTY POSITION_INDEPENDENT_CODE ON)

install(
  TARGETS ccfcrypto.host
  EXPORT ccf
  DESTINATION lib
)
