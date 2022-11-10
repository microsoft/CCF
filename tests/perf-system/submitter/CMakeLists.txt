set(SUBMITTER_DIR ${CCF_DIR}/tests/perf-system/submitter)

add_executable(
  submit ${SUBMITTER_DIR}/submit.cpp ${SUBMITTER_DIR}/handle_arguments.h
         ${SUBMITTER_DIR}/parquet_data.h
)

add_library(stdcxxhttp_parser.host "${HTTP_PARSER_SOURCES}")

set(CCFCRYPTO_SRC
    ${CCF_DIR}/src/crypto/base64.cpp
    ${CCF_DIR}/src/crypto/entropy.cpp
    ${CCF_DIR}/src/crypto/hash.cpp
    ${CCF_DIR}/src/crypto/sha256_hash.cpp
    ${CCF_DIR}/src/crypto/symmetric_key.cpp
    ${CCF_DIR}/src/crypto/key_pair.cpp
    ${CCF_DIR}/src/crypto/rsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/verifier.cpp
    ${CCF_DIR}/src/crypto/key_wrap.cpp
    ${CCF_DIR}/src/crypto/hmac.cpp
    ${CCF_DIR}/src/crypto/openssl/symmetric_key.cpp
    ${CCF_DIR}/src/crypto/openssl/public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/hash.cpp
    ${CCF_DIR}/src/crypto/openssl/rsa_public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/rsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/verifier.cpp
)

add_library(stdcxxccfcrypto.host STATIC "${CCFCRYPTO_SRC}")
target_link_libraries(stdcxxccfcrypto.host PUBLIC crypto)
target_link_libraries(stdcxxccfcrypto.host PUBLIC ssl)

target_link_libraries(
  submit PRIVATE stdcxxhttp_parser.host stdcxxccfcrypto.host arrow parquet
)

if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 9)
  target_link_libraries(submit PRIVATE c++fs)
endif()
install(TARGETS submit DESTINATION bin)
