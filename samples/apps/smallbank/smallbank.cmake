# Small Bank Client executable
add_client_exe(small_bank_client
  SRCS ${CMAKE_CURRENT_LIST_DIR}/clients/small_bank_client.cpp
)
target_link_libraries(small_bank_client PRIVATE secp256k1.host)

# SmallBank application
add_enclave_lib(smallbankenc
  ${CMAKE_CURRENT_LIST_DIR}/app/oe_sign.conf
  ${CCF_DIR}/src/apps/sample_key.pem
  SRCS ${CMAKE_CURRENT_LIST_DIR}/app/smallbank.cpp
)

if(BUILD_TESTS)
  ## Small Bank end to end and performance test
  add_perf_test(
    NAME small_bank_client_test
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/small_bank_client.py
    CLIENT_BIN ./small_bank_client
    VERIFICATION_FILE ${CMAKE_CURRENT_LIST_DIR}/tests/verify_small_bank.json
    ADDITIONAL_ARGS
      --max-writes-ahead 1000
  )

  add_perf_test(
    NAME small_bank_client_sigs_test
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/small_bank_client.py
    CLIENT_BIN ./small_bank_client
    VERIFICATION_FILE ${CMAKE_CURRENT_LIST_DIR}/tests/verify_small_bank_short.json
    ITERATIONS 2000
    ADDITIONAL_ARGS
      --label Small_Bank_Client_Sigs
      --max-writes-ahead 1000 --sign
  )

  add_perf_test(
    NAME small_bank_warmup_cooldown_client_test
    PYTHON_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/tests/small_bank_client.py
    CLIENT_BIN ./small_bank_client
    VERIFICATION_FILE ${CMAKE_CURRENT_LIST_DIR}/tests/verify_small_bank.json
    ADDITIONAL_ARGS
      --label Small_Bank_WarmupCooldown
      --max-writes-ahead 1 --warmup 1000 --cooldown 1000
  )
endif()
