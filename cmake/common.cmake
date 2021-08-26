# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CMAKE_MODULE_PATH "${CCF_DIR}/cmake;${CMAKE_MODULE_PATH}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

set(PYTHON unbuffer python3)

set(DISTRIBUTE_PERF_TESTS
    ""
    CACHE
      STRING
      "Hosts to which performance tests should be distributed, for example -n ssh://x.x.x.x -n ssh://x.x.x.x -n ssh://x.x.x.x"
)

if(DISTRIBUTE_PERF_TESTS)
  separate_arguments(NODES UNIX_COMMAND ${DISTRIBUTE_PERF_TESTS})
else()
  unset(NODES)
endif()

option(VERBOSE_LOGGING "Enable verbose logging" OFF)
set(TEST_HOST_LOGGING_LEVEL "info")
if(VERBOSE_LOGGING)
  add_compile_definitions(VERBOSE_LOGGING)
  set(TEST_HOST_LOGGING_LEVEL "debug")
endif()

option(NO_STRICT_TLS_CIPHERSUITES
       "Disable strict list of valid TLS ciphersuites" OFF
)
if(NO_STRICT_TLS_CIPHERSUITES)
  add_compile_definitions(NO_STRICT_TLS_CIPHERSUITES)
endif()

option(USE_NULL_ENCRYPTOR "Turn off encryption of ledger updates - debug only"
       OFF
)
if(USE_NULL_ENCRYPTOR)
  add_compile_definitions(USE_NULL_ENCRYPTOR)
endif()

option(SAN "Enable Address and Undefined Behavior Sanitizers" OFF)
option(DISABLE_QUOTE_VERIFICATION "Disable quote verification" OFF)
option(BUILD_END_TO_END_TESTS "Build end to end tests" ON)
option(COVERAGE "Enable coverage mapping" OFF)
option(SHUFFLE_SUITE "Shuffle end to end test suite" OFF)
option(LONG_TESTS "Enable long end-to-end tests" OFF)

option(ENABLE_BFT "Enable experimental BFT consensus at compile time" ON)
if(ENABLE_BFT)
  add_compile_definitions(ENABLE_BFT)
endif()

option(DEBUG_CONFIG "Enable non-production options options to aid debugging"
       OFF
)
if(DEBUG_CONFIG)
  add_compile_definitions(DEBUG_CONFIG)
endif()

option(USE_NLJSON_KV_SERIALISER "Use nlohmann JSON as the KV serialiser" OFF)
if(USE_NLJSON_KV_SERIALISER)
  add_compile_definitions(USE_NLJSON_KV_SERIALISER)
endif()

enable_language(ASM)

set(CCF_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
include_directories(${CCF_DIR}/include)
include_directories(${CCF_DIR}/src)

set(CCF_3RD_PARTY_EXPORTED_DIR "${CCF_DIR}/3rdparty/exported")
set(CCF_3RD_PARTY_INTERNAL_DIR "${CCF_DIR}/3rdparty/internal")

include_directories(SYSTEM ${CCF_3RD_PARTY_EXPORTED_DIR})
include_directories(SYSTEM ${CCF_3RD_PARTY_INTERNAL_DIR})

find_package(MbedTLS REQUIRED)

set(CLIENT_MBEDTLS_INCLUDE_DIR "${MBEDTLS_INCLUDE_DIRS}")
set(CLIENT_MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARIES}")

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/tools.cmake)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tools.cmake DESTINATION cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccf_app.cmake)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccf_app.cmake DESTINATION cmake)

if(SAN AND LVI_MITIGATIONS)
  message(
    FATAL_ERROR
      "Building with both SAN and LVI mitigations is unsafe and deadlocks - choose one"
  )
endif()

add_custom_command(
  COMMAND
    openenclave::oeedger8r ${CCF_DIR}/edl/ccf.edl --search-path ${OE_INCLUDEDIR}
    --trusted --trusted-dir ${CCF_GENERATED_DIR} --untrusted --untrusted-dir
    ${CCF_GENERATED_DIR}
  COMMAND mv ${CCF_GENERATED_DIR}/ccf_t.c ${CCF_GENERATED_DIR}/ccf_t.cpp
  COMMAND mv ${CCF_GENERATED_DIR}/ccf_u.c ${CCF_GENERATED_DIR}/ccf_u.cpp
  DEPENDS ${CCF_DIR}/edl/ccf.edl
  OUTPUT ${CCF_GENERATED_DIR}/ccf_t.cpp ${CCF_GENERATED_DIR}/ccf_u.cpp
  COMMENT "Generating code from EDL, and renaming to .cpp"
)

# Copy and install CCF utilities
set(CCF_UTILITIES keygenerator.sh scurl.sh submit_recovery_share.sh
                  verify_quote.sh
)
foreach(UTILITY ${CCF_UTILITIES})
  configure_file(
    ${CCF_DIR}/python/utils/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
  install(PROGRAMS ${CCF_DIR}/python/utils/${UTILITY} DESTINATION bin)
endforeach()

# Copy utilities from tests directory
set(CCF_TEST_UTILITIES tests.sh cimetrics_env.sh upload_pico_metrics.py
                       test_install.sh test_python_cli.sh
)
foreach(UTILITY ${CCF_TEST_UTILITIES})
  configure_file(
    ${CCF_DIR}/tests/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
endforeach()

# Install additional utilities
install(PROGRAMS ${CCF_DIR}/tests/sgxinfo.sh DESTINATION bin)

# Install getting_started scripts for VM creation and setup
install(
  DIRECTORY ${CCF_DIR}/getting_started/
  DESTINATION getting_started
  USE_SOURCE_PERMISSIONS
)

if("sgx" IN_LIST COMPILE_TARGETS)
  if(NOT DISABLE_QUOTE_VERIFICATION)
    set(QUOTES_ENABLED ON)
  endif()

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(DEFAULT_ENCLAVE_TYPE debug)
  endif()
else()
  set(DEFAULT_ENCLAVE_TYPE virtual)
endif()

set(HTTP_PARSER_SOURCES
    ${CCF_3RD_PARTY_EXPORTED_DIR}/llhttp/api.c
    ${CCF_3RD_PARTY_EXPORTED_DIR}/llhttp/http.c
    ${CCF_3RD_PARTY_EXPORTED_DIR}/llhttp/llhttp.c
)

set(CCF_ENDPOINTS_SOURCES
    ${CCF_DIR}/src/endpoints/endpoint.cpp
    ${CCF_DIR}/src/endpoints/endpoint_registry.cpp
    ${CCF_DIR}/src/endpoints/base_endpoint_registry.cpp
    ${CCF_DIR}/src/endpoints/common_endpoint_registry.cpp
)

set(CCF_ENDPOINTS_SOURCES
    ${CCF_DIR}/src/endpoints/endpoint.cpp
    ${CCF_DIR}/src/endpoints/endpoint_registry.cpp
    ${CCF_DIR}/src/endpoints/base_endpoint_registry.cpp
    ${CCF_DIR}/src/endpoints/common_endpoint_registry.cpp
    ${CCF_DIR}/src/enclave/enclave_time.cpp
)

find_library(CRYPTO_LIBRARY crypto)

list(APPEND COMPILE_LIBCXX -stdlib=libc++)
list(APPEND LINK_LIBCXX -lc++ -lc++abi -lc++fs -stdlib=libc++)

include(${CCF_DIR}/cmake/crypto.cmake)
include(${CCF_DIR}/cmake/quickjs.cmake)
include(${CCF_DIR}/cmake/sss.cmake)

# Unit test wrapper
function(add_unit_test name)
  add_executable(${name} ${CCF_DIR}/src/enclave/thread_local.cpp ${ARGN})
  target_compile_options(${name} PRIVATE ${COMPILE_LIBCXX})
  target_include_directories(
    ${name} PRIVATE src ${CCFCRYPTO_INC} ${CCF_DIR}/3rdparty/test
  )
  enable_coverage(${name})
  target_link_libraries(
    ${name} PRIVATE ${LINK_LIBCXX} ccfcrypto.host openenclave::oehost
  )
  add_san(${name})

  add_test(NAME ${name} COMMAND ${CCF_DIR}/tests/unit_test_wrapper.sh ${name})
  set_property(
    TEST ${name}
    APPEND
    PROPERTY LABELS unit_test
  )
endfunction()

# Test binary wrapper
function(add_test_bin name)
  add_executable(${name} ${CCF_DIR}/src/enclave/thread_local.cpp ${ARGN})
  target_compile_options(${name} PRIVATE ${COMPILE_LIBCXX})
  target_include_directories(${name} PRIVATE src ${CCFCRYPTO_INC})
  enable_coverage(${name})
  target_link_libraries(${name} PRIVATE ${LINK_LIBCXX} ccfcrypto.host)
  add_san(${name})
endfunction()

if("sgx" IN_LIST COMPILE_TARGETS)
  # Host Executable
  add_executable(
    cchost ${CCF_DIR}/src/host/main.cpp ${CCF_GENERATED_DIR}/ccf_u.cpp
  )

  add_warning_checks(cchost)
  target_compile_options(cchost PRIVATE ${COMPILE_LIBCXX})
  target_include_directories(cchost PRIVATE ${CCF_GENERATED_DIR})
  add_san(cchost)

  target_link_libraries(
    cchost
    PRIVATE uv
            ${CRYPTO_LIBRARY}
            ${CMAKE_DL_LIBS}
            ${CMAKE_THREAD_LIBS_INIT}
            ${LINK_LIBCXX}
            openenclave::oehost
            ccfcrypto.host
  )
  enable_quote_code(cchost)

  install(TARGETS cchost DESTINATION bin)
endif()

option(USE_SNMALLOC "should snmalloc be used" ON)

if("virtual" IN_LIST COMPILE_TARGETS)
  if(SAN OR NOT USE_SNMALLOC)
    set(SNMALLOC_LIB)
    set(SNMALLOC_CPP)
  else()

    set(SNMALLOC_ONLY_HEADER_LIBRARY ON)
    # Remove the following two lines once we upgrade to snmalloc 0.5.4
    set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
    set(USE_POSIX_COMMIT_CHECKS off)
    add_subdirectory(3rdparty/exported/snmalloc EXCLUDE_FROM_ALL)
    set(SNMALLOC_LIB snmalloc_lib)
    set(SNMALLOC_CPP src/enclave/snmalloc.cpp)
  endif()

  # Virtual Host Executable
  add_executable(cchost.virtual ${SNMALLOC_CPP} ${CCF_DIR}/src/host/main.cpp)
  target_compile_definitions(cchost.virtual PRIVATE -DVIRTUAL_ENCLAVE)
  target_compile_options(cchost.virtual PRIVATE ${COMPILE_LIBCXX})
  target_include_directories(
    cchost.virtual PRIVATE ${OE_INCLUDEDIR} ${CCF_GENERATED_DIR}
  )
  add_warning_checks(cchost.virtual)
  add_san(cchost.virtual)
  target_link_libraries(
    cchost.virtual
    PRIVATE uv
            ${SNMALLOC_LIB}
            ${CRYPTO_LIBRARY}
            ${CMAKE_DL_LIBS}
            ${CMAKE_THREAD_LIBS_INIT}
            ${LINK_LIBCXX}
            ccfcrypto.host
  )

  install(TARGETS cchost.virtual DESTINATION bin)
endif()

# Perf scenario executable
add_executable(
  scenario_perf_client ${CCF_DIR}/src/perf_client/scenario_perf_client.cpp
)
target_link_libraries(
  scenario_perf_client PRIVATE ${CMAKE_THREAD_LIBS_INIT} http_parser.host
                               ccfcrypto.host c++fs
)
install(TARGETS scenario_perf_client DESTINATION bin)

# HTTP parser
add_enclave_library_c(http_parser.enclave "${HTTP_PARSER_SOURCES}")
set_property(TARGET http_parser.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
install(
  TARGETS http_parser.enclave
  EXPORT ccf
  DESTINATION lib
)
add_library(http_parser.host "${HTTP_PARSER_SOURCES}")
set_property(TARGET http_parser.host PROPERTY POSITION_INDEPENDENT_CODE ON)
install(
  TARGETS http_parser.host
  EXPORT ccf
  DESTINATION lib
)

# CCF endpoints libs
add_enclave_library(ccf_endpoints.enclave "${CCF_ENDPOINTS_SOURCES}")
use_oe_mbedtls(ccf_endpoints.enclave)
add_warning_checks(ccf_endpoints.enclave)
install(
  TARGETS ccf_endpoints.enclave
  EXPORT ccf
  DESTINATION lib
)
add_host_library(ccf_endpoints.host "${CCF_ENDPOINTS_SOURCES}")
use_client_mbedtls(ccf_endpoints.host)
add_san(ccf_endpoints.host)
add_warning_checks(ccf_endpoints.host)
install(
  TARGETS ccf_endpoints.host
  EXPORT ccf
  DESTINATION lib
)

# Common test args for Python scripts starting up CCF networks
set(WORKER_THREADS
    0
    CACHE STRING "Number of worker threads to start on each CCF node"
)

set(CCF_NETWORK_TEST_DEFAULT_CONSTITUTION
    --constitution
    ${CCF_DIR}/src/runtime_config/default/actions.js
    --constitution
    ${CCF_DIR}/src/runtime_config/default/validate.js
    --constitution
    ${CCF_DIR}/src/runtime_config/default/resolve.js
    --constitution
    ${CCF_DIR}/src/runtime_config/default/apply.js
)
set(CCF_NETWORK_TEST_ARGS -l ${TEST_HOST_LOGGING_LEVEL} --worker-threads
                          ${WORKER_THREADS}
)

# SNIPPET_START: JS generic application
add_ccf_app(
  js_generic
  SRCS ${CCF_DIR}/src/apps/js_generic/js_generic.cpp
  LINK_LIBS_ENCLAVE quickjs.enclave -lgcc
  LINK_LIBS_VIRTUAL quickjs.host INSTALL_LIBS ON
)
sign_app_library(
  js_generic.enclave ${CCF_DIR}/src/apps/js_generic/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem INSTALL_LIBS ON
)
# SNIPPET_END: JS generic application

install(DIRECTORY ${CCF_DIR}/samples/apps/logging/js
        DESTINATION samples/logging
)

# Samples

# Helper for building clients inheriting from perf_client
function(add_client_exe name)

  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  add_executable(${name} ${PARSED_ARGS_SRCS})

  target_link_libraries(
    ${name} PRIVATE ${CMAKE_THREAD_LIBS_INIT} ccfcrypto.host
  )
  target_include_directories(
    ${name} PRIVATE ${CCF_DIR}/src/perf_client ${PARSED_ARGS_INCLUDE_DIRS}
  )

endfunction()

# Helper for building end-to-end function tests using the python infrastructure
function(add_e2e_test)
  cmake_parse_arguments(
    PARSE_ARGV 0 PARSED_ARGS ""
    "NAME;PYTHON_SCRIPT;LABEL;CURL_CLIENT;CONSENSUS;"
    "CONSTITUTION;ADDITIONAL_ARGS;CONFIGURATIONS"
  )

  if(NOT PARSED_ARGS_CONSTITUTION)
    set(PARSED_ARGS_CONSTITUTION ${CCF_NETWORK_TEST_DEFAULT_CONSTITUTION})
  endif()

  if(BUILD_END_TO_END_TESTS)
    add_test(
      NAME ${PARSED_ARGS_NAME}
      COMMAND
        ${PYTHON} ${PARSED_ARGS_PYTHON_SCRIPT} -b . --label ${PARSED_ARGS_NAME}
        ${CCF_NETWORK_TEST_ARGS} ${PARSED_ARGS_CONSTITUTION} --consensus
        ${PARSED_ARGS_CONSENSUS} ${PARSED_ARGS_ADDITIONAL_ARGS}
      CONFIGURATIONS ${PARSED_ARGS_CONFIGURATIONS}
    )

    # Make python test client framework importable
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY ENVIRONMENT "PYTHONPATH=${CCF_DIR}/tests:$ENV{PYTHONPATH}"
    )

    if(SHUFFLE_SUITE)
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "SHUFFLE_SUITE=1"
      )
    endif()

    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY LABELS e2e
    )
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY LABELS ${PARSED_ARGS_LABEL}
    )

    if(${PARSED_ARGS_CURL_CLIENT})
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "CURL_CLIENT=ON"
      )
    endif()
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY LABELS ${PARSED_ARGS_CONSENSUS}
    )

    if(DEFINED DEFAULT_ENCLAVE_TYPE)
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "DEFAULT_ENCLAVE_TYPE=${DEFAULT_ENCLAVE_TYPE}"
      )
    endif()
  endif()
endfunction()

# Helper for building end-to-end function tests using the sandbox
function(add_e2e_sandbox_test)
  cmake_parse_arguments(
    PARSE_ARGV 0 PARSED_ARGS "" "NAME;SCRIPT;LABEL;CONSENSUS;"
    "ADDITIONAL_ARGS;CONFIGURATIONS"
  )

  if(BUILD_END_TO_END_TESTS)
    add_test(NAME ${PARSED_ARGS_NAME} COMMAND ${PARSED_ARGS_SCRIPT})
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY LABELS e2e
    )

    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY LABELS e2e
    )
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY LABELS ${PARSED_ARGS_LABEL}
    )

    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY ENVIRONMENT "CONSENSUS=${PARSED_ARGS_CONSENSUS}"
    )
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY LABELS ${PARSED_ARGS_CONSENSUS}
    )

    if(DEFINED DEFAULT_ENCLAVE_TYPE)
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "ENCLAVE_TYPE=${DEFAULT_ENCLAVE_TYPE}"
      )
    else()
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "ENCLAVE_TYPE=release"
      )
    endif()
  endif()
endfunction()

# Helper for building end-to-end perf tests using the python infrastucture
function(add_perf_test)

  cmake_parse_arguments(
    PARSE_ARGV
    0
    PARSED_ARGS
    ""
    "NAME;PYTHON_SCRIPT;CONSTITUTION;CLIENT_BIN;VERIFICATION_FILE;LABEL;CONSENSUS"
    "ADDITIONAL_ARGS"
  )

  if(NOT PARSED_ARGS_CONSTITUTION)
    set(PARSED_ARGS_CONSTITUTION ${CCF_NETWORK_TEST_DEFAULT_CONSTITUTION})
  endif()

  if(PARSED_ARGS_VERIFICATION_FILE)
    set(VERIFICATION_ARG "--verify ${PARSED_ARGS_VERIFICATION_FILE}")
  else()
    unset(VERIFICATION_ARG)
  endif()

  set(TESTS_SUFFIX "")
  if("sgx" IN_LIST COMPILE_TARGETS)
    set(TESTS_SUFFIX "${TESTS_SUFFIX}_sgx")
  endif()

  if("cft" STREQUAL ${PARSED_ARGS_CONSENSUS})
    set(TESTS_SUFFIX "${TESTS_SUFFIX}_cft")
  elseif("bft" STREQUAL ${PARSED_ARGS_CONSENSUS})
    set(TESTS_SUFFIX "${TESTS_SUFFIX}_bft")
  endif()

  set(TEST_NAME "${PARSED_ARGS_NAME}${TESTS_SUFFIX}")

  if(PARSED_ARGS_LABEL)
    set(LABEL_ARG "${TEST_NAME}^")
  else()
    set(LABEL_ARG "${TEST_NAME}^")
  endif()

  add_test(
    NAME "${PARSED_ARGS_NAME}${TESTS_SUFFIX}"
    COMMAND
      ${PYTHON} ${PARSED_ARGS_PYTHON_SCRIPT} -b . -c ${PARSED_ARGS_CLIENT_BIN}
      ${CCF_NETWORK_TEST_ARGS} --consensus ${PARSED_ARGS_CONSENSUS}
      ${PARSED_ARGS_CONSTITUTION} --write-tx-times ${VERIFICATION_ARG} --label
      ${LABEL_ARG} --snapshot-tx-interval 10000 ${PARSED_ARGS_ADDITIONAL_ARGS}
      ${NODES}
  )

  # Make python test client framework importable
  set_property(
    TEST ${TEST_NAME}
    APPEND
    PROPERTY ENVIRONMENT "PYTHONPATH=${CCF_DIR}/tests:$ENV{PYTHONPATH}"
  )
  if(DEFINED DEFAULT_ENCLAVE_TYPE)
    set_property(
      TEST ${TEST_NAME}
      APPEND
      PROPERTY ENVIRONMENT "DEFAULT_ENCLAVE_TYPE=${DEFAULT_ENCLAVE_TYPE}"
    )
  endif()
  set_property(
    TEST ${TEST_NAME}
    APPEND
    PROPERTY LABELS perf
  )
  set_property(
    TEST ${TEST_NAME}
    APPEND
    PROPERTY LABELS ${PARSED_ARGS_CONSENSUS}
  )
endfunction()

# Picobench wrapper
function(add_picobench name)
  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  add_executable(${name} ${PARSED_ARGS_SRCS})

  target_include_directories(${name} PRIVATE src ${PARSED_ARGS_INCLUDE_DIRS})

  target_link_libraries(
    ${name} PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${PARSED_ARGS_LINK_LIBS}
                    ccfcrypto.host
  )

  # -Wall -Werror catches a number of warnings in picobench
  target_include_directories(${name} SYSTEM PRIVATE 3rdparty/test)

  add_test(
    NAME ${name}
    COMMAND
      bash -c
      "$<TARGET_FILE:${name}> --samples=1000 --out-fmt=csv --output=${name}.csv && cat ${name}.csv"
  )

  set_property(TEST ${name} PROPERTY LABELS benchmark)
endfunction()
