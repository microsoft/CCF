# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# Small Bank Client executable
add_client_exe(
  small_bank_client
  SRCS ${CMAKE_CURRENT_LIST_DIR}/clients/small_bank_client.cpp
)
target_link_libraries(small_bank_client PRIVATE secp256k1.host http_parser.host)

# SmallBank application
add_ccf_app(smallbank SRCS ${CMAKE_CURRENT_LIST_DIR}/app/smallbank.cpp)
sign_app_library(
  smallbank.enclave ${CMAKE_CURRENT_LIST_DIR}/app/oe_sign.conf
  ${CCF_DIR}/src/apps/sample_key.pem
)

if(BUILD_TESTS)
  # Small Bank end to end and performance test
  if(PBFT)
    set(SMALL_BANK_VERIFICATION_FILE
        ${CMAKE_CURRENT_LIST_DIR}/tests/verify_small_bank_50k.json
    )
    set(SMALL_BANK_ITERATIONS 50000)
  else()
    set(SMALL_BANK_VERIFICATION_FILE
        ${CMAKE_CURRENT_LIST_DIR}/tests/verify_small_bank.json
    )
    set(SMALL_BANK_ITERATIONS 200000)
  endif()
  # TODO: Fix signed HTTP RPCs with PBFT
  if(NOT (PBFT AND HTTP))
    add_perf_test(
      NAME small_bank_client_test
      PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/small_bank_client.py
      CLIENT_BIN ./small_bank_client
      VERIFICATION_FILE ${SMALL_BANK_VERIFICATION_FILE}
      LABEL SB
      ADDITIONAL_ARGS
        --transactions ${SMALL_BANK_ITERATIONS} --max-writes-ahead 1000
        --metrics-file small_bank_metrics.json
    )
  endif()

  if(PBFT)
    set(SMALL_BANK_SIGNED_VERIFICATION_FILE
        ${CMAKE_CURRENT_LIST_DIR}/tests/verify_small_bank_20k.json
    )
    set(SMALL_BANK_SIGNED_ITERATIONS 20000)
  elseif(${SERVICE_IDENTITY_CURVE_CHOICE} STREQUAL "secp256k1_bitcoin")
    set(SMALL_BANK_SIGNED_VERIFICATION_FILE
        ${CMAKE_CURRENT_LIST_DIR}/tests/verify_small_bank_50k.json
    )
    set(SMALL_BANK_SIGNED_ITERATIONS 50000)
  else()
    set(SMALL_BANK_SIGNED_VERIFICATION_FILE
        ${CMAKE_CURRENT_LIST_DIR}/tests/verify_small_bank_2k.json
    )
    set(SMALL_BANK_SIGNED_ITERATIONS 2000)
  endif()

  # These tests require client-signed signatures: - PBFT doesn't yet verify
  # these correctly - HTTP C++ perf clients don't currently sign correctly
  if(NOT PBFT AND NOT HTTP)
    add_perf_test(
      NAME small_bank_sigs_client_test
      PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/small_bank_client.py
      CLIENT_BIN ./small_bank_client
      VERIFICATION_FILE ${SMALL_BANK_SIGNED_VERIFICATION_FILE}
      LABEL "SB_sig"
      ADDITIONAL_ARGS
        --transactions
        ${SMALL_BANK_SIGNED_ITERATIONS}
        --max-writes-ahead
        1000
        --sign
        --metrics-file
        small_bank_sigs_metrics.json
    )

    # It is better to run performance tests with forwarding on different
    # machines (i.e. nodes and clients)
    add_perf_test(
      NAME small_bank_sigs_forwarding
      PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/small_bank_client.py
      CLIENT_BIN ./small_bank_client
      LABEL "SB_sig_fwd"
      ADDITIONAL_ARGS
        --transactions
        ${SMALL_BANK_SIGNED_ITERATIONS}
        --max-writes-ahead
        1000
        --metrics-file
        small_bank_fwd_metrics.json
        -n
        localhost
        -n
        localhost
        -cn
        localhost
        --send-tx-to
        backups
        --sign
    )
  endif()
endif()
