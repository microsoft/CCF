set(EDL_FILE ${CMAKE_CURRENT_LIST_DIR}/crypto_bench.edl)
set(CFG_FILE ${CMAKE_CURRENT_LIST_DIR}/crypto_bench.cfg)
set(KEY_FILE ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem)

# Enclave

add_custom_command(
  OUTPUT crypto_bench_t.h crypto_bench_t.c
  DEPENDS ${EDL_FILE} openenclave::oeedger8r
  COMMAND openenclave::oeedger8r --trusted ${EDL_FILE} --search-path
          ${OE_INCLUDEDIR}
)

add_library(
  crypto_bench_enclave SHARED
  src/crypto/test/bench.cpp src/enclave/thread_local.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/crypto_bench_t.c
)

target_compile_definitions(crypto_bench_enclave PRIVATE INSIDE_ENCLAVE)

target_include_directories(
  crypto_bench_enclave
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR} SYSTEM
  PRIVATE 3rdparty/test
)

target_link_libraries(
  crypto_bench_enclave ccfcrypto.enclave ${OE_TARGET_ENCLAVE_AND_STD} -lgcc
)

add_custom_command(
  OUTPUT ${KEY_FILE} COMMAND openssl genrsa -out ${KEY_FILE} -3 3072
)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libcrypto_bench_enclave.signed
  COMMAND
    openenclave::oesign sign -e
    ${CMAKE_CURRENT_BINARY_DIR}/libcrypto_bench_enclave.so -c ${CFG_FILE} -k
    ${KEY_FILE}
  DEPENDS crypto_bench_enclave ${KEY_FILE}
)

# Host

add_custom_command(
  OUTPUT crypto_bench_u.h crypto_bench_u.c
  DEPENDS ${EDL_FILE} openenclave::oeedger8r
          ${CMAKE_CURRENT_BINARY_DIR}/libcrypto_bench_enclave.signed
  COMMAND openenclave::oeedger8r --untrusted ${EDL_FILE} --search-path
          ${OE_INCLUDEDIR}
)

add_executable(
  crypto_bench_host src/crypto/test/bench-enclave/host.cpp
                    ${CMAKE_CURRENT_BINARY_DIR}/crypto_bench_u.c
)

target_include_directories(
  crypto_bench_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OE_INCLUDEDIR}
)

target_link_libraries(crypto_bench_host openenclave::oehost)
