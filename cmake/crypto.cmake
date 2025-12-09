# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CCFCRYPTO_SRC
    ${CCF_DIR}/src/crypto/base64.cpp
    ${CCF_DIR}/src/crypto/entropy.cpp
    ${CCF_DIR}/src/crypto/hash.cpp
    ${CCF_DIR}/src/crypto/sha256_hash.cpp
    ${CCF_DIR}/src/crypto/symmetric_key.cpp
    ${CCF_DIR}/src/crypto/eddsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/verifier.cpp
    ${CCF_DIR}/src/crypto/key_wrap.cpp
    ${CCF_DIR}/src/crypto/hmac.cpp
    ${CCF_DIR}/src/crypto/pem.cpp
    ${CCF_DIR}/src/crypto/ecdsa.cpp
    ${CCF_DIR}/src/crypto/cose.cpp
    ${CCF_DIR}/src/crypto/openssl/symmetric_key.cpp
    ${CCF_DIR}/src/crypto/openssl/ec_public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/ec_key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/eddsa_public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/eddsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/hash.cpp
    ${CCF_DIR}/src/crypto/openssl/rsa_public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/rsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/verifier.cpp
    ${CCF_DIR}/src/crypto/openssl/cose_verifier.cpp
    ${CCF_DIR}/src/crypto/openssl/cose_sign.cpp
    ${CCF_DIR}/src/crypto/sharing.cpp
)

find_library(CRYPTO_LIBRARY crypto)
find_library(TLS_LIBRARY ssl)

add_library(ccfcrypto STATIC ${CCFCRYPTO_SRC})
add_san(ccfcrypto)
add_tidy(ccfcrypto)
target_compile_options(ccfcrypto PUBLIC ${COMPILE_LIBCXX})
target_link_options(ccfcrypto PUBLIC ${LINK_LIBCXX})

target_link_libraries(ccfcrypto PUBLIC qcbor)
target_link_libraries(ccfcrypto PUBLIC t_cose)
target_link_libraries(ccfcrypto PUBLIC crypto)
target_link_libraries(ccfcrypto PUBLIC ssl)
set_property(TARGET ccfcrypto PROPERTY POSITION_INDEPENDENT_CODE ON)

install(
  TARGETS ccfcrypto
  EXPORT ccf
  DESTINATION lib
)
