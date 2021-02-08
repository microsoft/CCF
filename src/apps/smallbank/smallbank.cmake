# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# Small Bank Client executable

add_picobench(
  small_bank_serdes_bench
  SRCS ${CMAKE_CURRENT_LIST_DIR}/tests/small_bank_serdes_bench.cpp
       src/crypto/symmetric_key.cpp src/enclave/thread_local.cpp
  INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}
  LINK_LIBS ccfcrypto.host crypto
)

add_client_exe(
  small_bank_client
  SRCS ${CMAKE_CURRENT_LIST_DIR}/clients/small_bank_client.cpp
)
target_link_libraries(small_bank_client PRIVATE http_parser.host ccfcrypto.host)

# SmallBank application
add_ccf_app(smallbank SRCS ${CMAKE_CURRENT_LIST_DIR}/app/smallbank.cpp)
sign_app_library(
  smallbank.enclave ${CMAKE_CURRENT_LIST_DIR}/app/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

function(get_verification_file iterations output_var)
  math(EXPR thousand_iterations "${iterations} / 1000")
  set(proposed_name
      ${CMAKE_CURRENT_LIST_DIR}/tests/verify_small_bank_${thousand_iterations}k.json
  )
  if(NOT EXISTS "${proposed_name}")
    message(
      FATAL_ERROR
        "Could not find verification file for ${iterations} iterations (looking for ${proposed_name})"
    )
  endif()
  set(${output_var}
      ${proposed_name}
      PARENT_SCOPE
  )
endfunction()

set(SMALL_BANK_SIGNED_ITERATIONS 50000)
get_verification_file(
  ${SMALL_BANK_SIGNED_ITERATIONS} SMALL_BANK_SIGNED_VERIFICATION_FILE
)

if(BUILD_TESTS)
  # Small Bank end to end and performance test

  set(SMALL_BANK_ITERATIONS 200000)
  get_verification_file(${SMALL_BANK_ITERATIONS} SMALL_BANK_VERIFICATION_FILE)

  foreach(CONSENSUS ${CONSENSUSES})
    add_perf_test(
      NAME sb
      PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/small_bank_client.py
      CLIENT_BIN ./small_bank_client
      VERIFICATION_FILE ${SMALL_BANK_VERIFICATION_FILE}
      CONSENSUS ${CONSENSUS}
      ADDITIONAL_ARGS
        --transactions ${SMALL_BANK_ITERATIONS} --max-writes-ahead 250
        --metrics-file small_bank_cft_metrics.json
    )
  endforeach()

  add_perf_test(
    NAME sb_ws
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/small_bank_client.py
    CLIENT_BIN ./small_bank_client
    VERIFICATION_FILE ${SMALL_BANK_VERIFICATION_FILE}
    CONSENSUS cft
    ADDITIONAL_ARGS
      --transactions
      ${SMALL_BANK_ITERATIONS}
      --max-writes-ahead
      250
      --metrics-file
      small_bank_cft_metrics.json
      --use-websockets
  )

  add_perf_test(
    NAME sb_sig
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/small_bank_client.py
    CLIENT_BIN ./small_bank_client
    VERIFICATION_FILE ${SMALL_BANK_SIGNED_VERIFICATION_FILE}
    CONSENSUS cft
    ADDITIONAL_ARGS
      --transactions
      ${SMALL_BANK_SIGNED_ITERATIONS}
      --max-writes-ahead
      1000
      --sign
      --participants-curve
      "secp256r1"
      --metrics-file
      small_bank_cft_sigs_metrics.json
  )

endif()
