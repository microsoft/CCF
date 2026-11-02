# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

option(USE_RUST_SHAMIR "Use the Rust Shamir secret-sharing backend" ON)
if(USE_RUST_SHAMIR)
  set(CCF_SHAMIR_SOURCE ${CCF_DIR}/src/crypto/sharing_rust.cpp)
  set(CCF_SHAMIR_REFERENCE_SOURCE ${CCF_DIR}/src/crypto/sharing.cpp)
  message(STATUS "Shamir secret-sharing backend: Rust")
else()
  set(CCF_SHAMIR_SOURCE ${CCF_DIR}/src/crypto/sharing.cpp)
  set(CCF_SHAMIR_REFERENCE_SOURCE ${CCF_DIR}/src/crypto/sharing_rust.cpp)
  message(STATUS "Shamir secret-sharing backend: C++")
endif()

set(
  CCFCRYPTO_SRC
  ${CCF_DIR}/src/crypto/base64.cpp
  ${CCF_DIR}/src/crypto/entropy.cpp
  ${CCF_DIR}/src/crypto/hash.cpp
  ${CCF_DIR}/src/crypto/public_key.cpp
  ${CCF_DIR}/src/crypto/sha256_hash.cpp
  ${CCF_DIR}/src/crypto/symmetric_key.cpp
  ${CCF_DIR}/src/crypto/eddsa_key_pair.cpp
  ${CCF_DIR}/src/crypto/verifier.cpp
  ${CCF_DIR}/src/crypto/key_wrap.cpp
  ${CCF_DIR}/src/crypto/hmac.cpp
  ${CCF_DIR}/src/crypto/pem.cpp
  ${CCF_DIR}/src/crypto/ecdsa.cpp
  ${CCF_DIR}/src/crypto/cose.cpp
  ${CCF_DIR}/src/crypto/cose_key.cpp
  ${CCF_DIR}/src/crypto/openssl/symmetric_key.cpp
  ${CCF_DIR}/src/crypto/openssl/ec_public_key.cpp
  ${CCF_DIR}/src/crypto/openssl/ec_key_pair.cpp
  ${CCF_DIR}/src/crypto/openssl/eddsa_public_key.cpp
  ${CCF_DIR}/src/crypto/openssl/eddsa_key_pair.cpp
  ${CCF_DIR}/src/crypto/openssl/mldsa_public_key.cpp
  ${CCF_DIR}/src/crypto/openssl/mldsa_key_pair.cpp
  ${CCF_DIR}/src/crypto/openssl/hash.cpp
  ${CCF_DIR}/src/crypto/openssl/rsa_public_key.cpp
  ${CCF_DIR}/src/crypto/openssl/rsa_key_pair.cpp
  ${CCF_DIR}/src/crypto/openssl/verifier.cpp
  ${CCF_DIR}/src/crypto/openssl/cose_verifier.cpp
  ${CCF_SHAMIR_SOURCE}
)

find_library(CRYPTO_LIBRARY crypto)
find_library(TLS_LIBRARY ssl)

add_library(ccfcrypto STATIC ${CCFCRYPTO_SRC})
add_warning_checks(ccfcrypto)
target_compile_options(
  ccfcrypto
  PRIVATE $<$<COMPILE_LANG_AND_ID:CXX,Clang>:-Wno-vla-cxx-extension>
)
add_san(ccfcrypto)
add_hardening(ccfcrypto)
add_tidy(ccfcrypto)
enable_coverage(ccfcrypto)

target_link_libraries(ccfcrypto PUBLIC crypto ssl ccf_threading)
target_link_libraries(ccfcrypto PUBLIC ccf_rs)
set_property(TARGET ccfcrypto PROPERTY POSITION_INDEPENDENT_CODE ON)

install(TARGETS ccfcrypto EXPORT ccf DESTINATION lib)
