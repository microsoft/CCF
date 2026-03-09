# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CCFCRYPTO_SRC
    ${CCF_DIR}/src/crypto/base64.cpp
    ${CCF_DIR}/src/crypto/entropy.cpp
    ${CCF_DIR}/src/crypto/hash.cpp
    ${CCF_DIR}/src/crypto/sha256_hash.cpp
    ${CCF_DIR}/src/crypto/symmetric_key.cpp
    ${CCF_DIR}/src/crypto/key_pair.cpp
    ${CCF_DIR}/src/crypto/eddsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/rsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/verifier.cpp
    ${CCF_DIR}/src/crypto/key_wrap.cpp
    ${CCF_DIR}/src/crypto/hmac.cpp
    ${CCF_DIR}/src/crypto/pem.cpp
    ${CCF_DIR}/src/crypto/ecdsa.cpp
    ${CCF_DIR}/src/crypto/cose.cpp
    ${CCF_DIR}/src/crypto/openssl/symmetric_key.cpp
    ${CCF_DIR}/src/crypto/openssl/public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/key_pair.cpp
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

if(COMPILE_TARGET STREQUAL "snp")
  add_library(ccfcrypto.snp ${CCFCRYPTO_SRC})
  add_san(ccfcrypto.snp)
  add_tidy(ccfcrypto.snp)
  target_compile_options(ccfcrypto.snp PUBLIC ${COMPILE_LIBCXX})
  target_link_options(ccfcrypto.snp PUBLIC ${LINK_LIBCXX})
  target_link_libraries(ccfcrypto.snp PUBLIC qcbor.snp)
  target_link_libraries(ccfcrypto.snp PUBLIC t_cose.snp)
  target_link_libraries(ccfcrypto.snp PUBLIC crypto)
  target_link_libraries(ccfcrypto.snp PUBLIC ssl)
  set_property(TARGET ccfcrypto.snp PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_compile_definitions(ccfcrypto.snp PRIVATE CCF_LOGGER_NO_DEPRECATE)

  if(CCF_DEVEL)
    install(
      TARGETS ccfcrypto.snp
      EXPORT ccf
      DESTINATION lib
    )
  endif()
endif()

find_library(CRYPTO_LIBRARY crypto)
find_library(TLS_LIBRARY ssl)

add_library(ccfcrypto.host STATIC ${CCFCRYPTO_SRC})
add_san(ccfcrypto.host)
add_tidy(ccfcrypto.host)
target_compile_options(ccfcrypto.host PUBLIC ${COMPILE_LIBCXX})
target_link_options(ccfcrypto.host PUBLIC ${LINK_LIBCXX})

target_link_libraries(ccfcrypto.host PUBLIC qcbor.host)
target_link_libraries(ccfcrypto.host PUBLIC t_cose.host)
target_link_libraries(ccfcrypto.host PUBLIC crypto)
target_link_libraries(ccfcrypto.host PUBLIC ssl)
set_property(TARGET ccfcrypto.host PROPERTY POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(ccfcrypto.host PRIVATE CCF_LOGGER_NO_DEPRECATE)

if(INSTALL_VIRTUAL_LIBRARIES)
  install(
    TARGETS ccfcrypto.host
    EXPORT ccf
    DESTINATION lib
  )
endif()
