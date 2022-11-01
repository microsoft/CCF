# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CMAKE_MODULE_PATH "${CCF_DIR}/cmake;${CMAKE_MODULE_PATH}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

function(message)
  if(NOT MESSAGE_QUIET)
    _message(${ARGN})
  endif()
endfunction()

option(PROFILE_TESTS "Profile tests" OFF)
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

option(VERBOSE_LOGGING "Enable verbose, unsafe logging of enclave code" OFF)
set(TEST_HOST_LOGGING_LEVEL "info")
if(VERBOSE_LOGGING)
  set(TEST_HOST_LOGGING_LEVEL "trace")
  add_compile_definitions(VERBOSE_LOGGING)
endif()

option(USE_NULL_ENCRYPTOR "Turn off encryption of ledger updates - debug only"
       OFF
)
if(USE_NULL_ENCRYPTOR)
  add_compile_definitions(USE_NULL_ENCRYPTOR)
endif()

option(SAN "Enable Address and Undefined Behavior Sanitizers" OFF)
option(BUILD_END_TO_END_TESTS "Build end to end tests" ON)
option(COVERAGE "Enable coverage mapping" OFF)
option(SHUFFLE_SUITE "Shuffle end to end test suite" OFF)
option(LONG_TESTS "Enable long end-to-end tests" OFF)
option(KV_STATE_RB "Enable RBMap as underlying KV state implementation" OFF)
if(KV_STATE_RB)
  add_compile_definitions(KV_STATE_RB)
endif()

option(ENABLE_BFT "Enable experimental BFT consensus at compile time" OFF)
if(ENABLE_BFT)
  add_compile_definitions(ENABLE_BFT)
endif()

option(ENABLE_2TX_RECONFIG "Enable experimental 2-transaction reconfiguration"
       OFF
)
if(ENABLE_2TX_RECONFIG)
  add_compile_definitions(ENABLE_2TX_RECONFIG)
endif()

# This option controls whether to link virtual builds against snmalloc rather
# than use the system allocator. In builds using Open Enclave, enclave
# allocation is managed separately and enabling snmalloc is done by linking
# openenclave::oesnmalloc
option(USE_SNMALLOC "Link virtual build against snmalloc" ON)

enable_language(ASM)

set(CCF_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
include_directories(${CCF_DIR}/include)
include_directories(${CCF_DIR}/src)

set(CCF_3RD_PARTY_EXPORTED_DIR "${CCF_DIR}/3rdparty/exported")
set(CCF_3RD_PARTY_INTERNAL_DIR "${CCF_DIR}/3rdparty/internal")

include_directories(SYSTEM ${CCF_3RD_PARTY_EXPORTED_DIR})
include_directories(SYSTEM ${CCF_3RD_PARTY_INTERNAL_DIR})

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
set(CCF_TEST_UTILITIES
    tests.sh
    cimetrics_env.sh
    upload_pico_metrics.py
    test_install.sh
    docker_wrap.sh
    config.jinja
    recovery_benchmark.sh
)
foreach(UTILITY ${CCF_TEST_UTILITIES})
  configure_file(
    ${CCF_DIR}/tests/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
endforeach()

# Install additional utilities
install(PROGRAMS ${CCF_DIR}/samples/scripts/sgxinfo.sh DESTINATION bin)
install(PROGRAMS ${CCF_DIR}/samples/scripts/snpinfo.sh DESTINATION bin)
install(FILES ${CCF_DIR}/tests/config.jinja DESTINATION bin)

if(SAN)
  install(FILES ${CCF_DIR}/src/ubsan.suppressions DESTINATION bin)
endif()

# Install getting_started scripts for VM creation and setup
install(
  DIRECTORY ${CCF_DIR}/getting_started/
  DESTINATION getting_started
  USE_SOURCE_PERMISSIONS
)

if(COMPILE_TARGET STREQUAL "sgx")
  # While virtual libraries need to be built for sgx for unit tests, these do
  # not get installed to minimise installation size
  set(INSTALL_VIRTUAL_LIBRARIES OFF)

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(DEFAULT_ENCLAVE_TYPE debug)
  endif()
else()
  set(INSTALL_VIRTUAL_LIBRARIES ON)
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
    ${CCF_DIR}/src/endpoints/json_handler.cpp
    ${CCF_DIR}/src/endpoints/authentication/cose_auth.cpp
    ${CCF_DIR}/src/endpoints/authentication/cert_auth.cpp
    ${CCF_DIR}/src/endpoints/authentication/empty_auth.cpp
    ${CCF_DIR}/src/endpoints/authentication/jwt_auth.cpp
    ${CCF_DIR}/src/endpoints/authentication/sig_auth.cpp
    ${CCF_DIR}/src/enclave/enclave_time.cpp
    ${CCF_DIR}/src/indexing/strategies/seqnos_by_key_bucketed.cpp
    ${CCF_DIR}/src/indexing/strategies/seqnos_by_key_in_memory.cpp
    ${CCF_DIR}/src/indexing/strategies/visit_each_entry_in_map.cpp
    ${CCF_DIR}/src/node/historical_queries_adapter.cpp
    ${CCF_DIR}/src/node/receipt.cpp
)

find_library(CRYPTO_LIBRARY crypto)
find_library(TLS_LIBRARY ssl)

include(${CCF_DIR}/cmake/crypto.cmake)
include(${CCF_DIR}/cmake/quickjs.cmake)
include(${CCF_DIR}/cmake/sss.cmake)
include(${CCF_DIR}/cmake/nghttp2.cmake)
include(${CCF_DIR}/cmake/qcbor.cmake)
include(${CCF_DIR}/cmake/t_cose.cmake)
set(MESSAGE_QUIET ON)
include(${CCF_DIR}/cmake/protobuf.cmake)
unset(MESSAGE_QUIET)

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

  add_test(NAME ${name} COMMAND ${name})
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

# Host Executable
if(SAN OR NOT USE_SNMALLOC)
  set(SNMALLOC_LIB)
else()
  set(SNMALLOC_ONLY_HEADER_LIBRARY ON)
  # Remove the following two lines once we upgrade to snmalloc 0.5.4
  set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
  set(USE_POSIX_COMMIT_CHECKS off)
  add_subdirectory(3rdparty/exported/snmalloc EXCLUDE_FROM_ALL)
  set(SNMALLOC_LIB snmalloc_lib)
  list(APPEND CCHOST_SOURCES src/host/snmalloc.cpp)
endif()

list(APPEND CCHOST_SOURCES ${CCF_DIR}/src/host/main.cpp)

if(COMPILE_TARGET STREQUAL "sgx")
  list(APPEND CCHOST_SOURCES ${CCF_GENERATED_DIR}/ccf_u.cpp)
endif()

add_executable(cchost ${CCHOST_SOURCES})

add_warning_checks(cchost)
add_san(cchost)

target_compile_options(cchost PRIVATE ${COMPILE_LIBCXX})
target_include_directories(cchost PRIVATE ${CCF_GENERATED_DIR})

# Host is always built with verbose logging enabled, regardless of CMake option
target_compile_definitions(cchost PRIVATE VERBOSE_LOGGING)

if(COMPILE_TARGET STREQUAL "sgx")
  target_compile_definitions(cchost PUBLIC PLATFORM_SGX)
elseif(COMPILE_TARGET STREQUAL "snp")
  target_compile_definitions(cchost PUBLIC PLATFORM_SNP)
elseif(COMPILE_TARGET STREQUAL "virtual")
  target_compile_definitions(cchost PUBLIC PLATFORM_VIRTUAL)
endif()

target_link_libraries(
  cchost
  PRIVATE uv
          ${SNMALLOC_LIB}
          ${TLS_LIBRARY}
          ${CMAKE_DL_LIBS}
          ${CMAKE_THREAD_LIBS_INIT}
          ${LINK_LIBCXX}
          ccfcrypto.host
)
if(COMPILE_TARGET STREQUAL "sgx")
  target_link_libraries(cchost PRIVATE openenclave::oehost)
endif()

install(TARGETS cchost DESTINATION bin)

# Perf scenario executable
add_executable(
  scenario_perf_client ${CCF_DIR}/src/clients/perf/scenario_perf_client.cpp
)
if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 9)
  target_link_libraries(
    scenario_perf_client PRIVATE ${CMAKE_THREAD_LIBS_INIT} http_parser.host
                                 ccfcrypto.host
  )
else()
  target_link_libraries(
    scenario_perf_client PRIVATE ${CMAKE_THREAD_LIBS_INIT} http_parser.host
                                 ccfcrypto.host c++fs
  )
endif()
install(TARGETS scenario_perf_client DESTINATION bin)

# HTTP parser
if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library_c(http_parser.enclave "${HTTP_PARSER_SOURCES}")
  install(
    TARGETS http_parser.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

add_library(http_parser.host "${HTTP_PARSER_SOURCES}")
set_property(TARGET http_parser.host PROPERTY POSITION_INDEPENDENT_CODE ON)
if(INSTALL_VIRTUAL_LIBRARIES)
  install(
    TARGETS http_parser.host
    EXPORT ccf
    DESTINATION lib
  )
endif()

# CCF kv libs
set(CCF_KV_SOURCES ${CCF_DIR}/src/kv/tx.cpp
                   ${CCF_DIR}/src/kv/untyped_map_handle.cpp
)

if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library(ccf_kv.enclave "${CCF_KV_SOURCES}")
  add_warning_checks(ccf_kv.enclave)
  install(
    TARGETS ccf_kv.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()
add_host_library(ccf_kv.host "${CCF_KV_SOURCES}")
add_san(ccf_kv.host)
add_warning_checks(ccf_kv.host)
if(INSTALL_VIRTUAL_LIBRARIES)
  install(
    TARGETS ccf_kv.host
    EXPORT ccf
    DESTINATION lib
  )
endif()

# CCF endpoints libs
if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library(ccf_endpoints.enclave "${CCF_ENDPOINTS_SOURCES}")
  target_link_libraries(ccf_endpoints.enclave PUBLIC qcbor.enclave)
  target_link_libraries(ccf_endpoints.enclave PUBLIC t_cose.enclave)
  add_warning_checks(ccf_endpoints.enclave)
  install(
    TARGETS ccf_endpoints.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

add_host_library(ccf_endpoints.host "${CCF_ENDPOINTS_SOURCES}")
target_link_libraries(ccf_endpoints.host PUBLIC qcbor.host)
target_link_libraries(ccf_endpoints.host PUBLIC t_cose.host)
add_san(ccf_endpoints.host)
add_warning_checks(ccf_endpoints.host)

if(INSTALL_VIRTUAL_LIBRARIES)
  install(
    TARGETS ccf_endpoints.host
    EXPORT ccf
    DESTINATION lib
  )
endif()

# Common test args for Python scripts starting up CCF networks
set(WORKER_THREADS
    0
    CACHE STRING "Number of worker threads to start on each CCF node"
)

set(CCF_NETWORK_TEST_DEFAULT_CONSTITUTION
    --constitution
    ${CCF_DIR}/samples/constitutions/default/actions.js
    --constitution
    ${CCF_DIR}/samples/constitutions/default/validate.js
    --constitution
    ${CCF_DIR}/samples/constitutions/default/resolve.js
    --constitution
    ${CCF_DIR}/samples/constitutions/default/apply.js
)
set(CCF_NETWORK_TEST_ARGS --host-log-level ${TEST_HOST_LOGGING_LEVEL}
                          --worker-threads ${WORKER_THREADS}
)

if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library(js_openenclave.enclave ${CCF_DIR}/src/js/openenclave.cpp)
  target_link_libraries(js_openenclave.enclave PUBLIC ccf.enclave)
  add_lvi_mitigations(js_openenclave.enclave)
  install(
    TARGETS js_openenclave.enclave
    EXPORT ccf
    DESTINATION lib
  )
elseif(COMPILE_TARGET STREQUAL "snp")
  add_library(js_openenclave.virtual STATIC ${CCF_DIR}/src/js/openenclave.cpp)
  add_san(js_openenclave.virtual)
  target_link_libraries(js_openenclave.virtual PUBLIC ccf.virtual)
  target_compile_options(js_openenclave.virtual PRIVATE ${COMPILE_LIBCXX})
  target_compile_definitions(
    js_openenclave.virtual PUBLIC INSIDE_ENCLAVE VIRTUAL_ENCLAVE
                                  _LIBCPP_HAS_THREAD_API_PTHREAD PLATFORM_SNP
  )
  set_property(
    TARGET js_openenclave.virtual PROPERTY POSITION_INDEPENDENT_CODE ON
  )
  install(
    TARGETS js_openenclave.virtual
    EXPORT ccf
    DESTINATION lib
  )
elseif(COMPILE_TARGET STREQUAL "virtual")
  add_library(js_openenclave.virtual STATIC ${CCF_DIR}/src/js/openenclave.cpp)
  add_san(js_openenclave.virtual)
  target_link_libraries(js_openenclave.virtual PUBLIC ccf.virtual)
  target_compile_options(js_openenclave.virtual PRIVATE ${COMPILE_LIBCXX})
  target_compile_definitions(
    js_openenclave.virtual
    PUBLIC INSIDE_ENCLAVE VIRTUAL_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD
           PLATFORM_VIRTUAL
  )
  set_property(
    TARGET js_openenclave.virtual PROPERTY POSITION_INDEPENDENT_CODE ON
  )
  install(
    TARGETS js_openenclave.virtual
    EXPORT ccf
    DESTINATION lib
  )
endif()

if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library(
    js_generic_base.enclave ${CCF_DIR}/src/apps/js_generic/js_generic_base.cpp
  )
  target_link_libraries(js_generic_base.enclave PUBLIC ccf.enclave)
  add_lvi_mitigations(js_generic_base.enclave)
  install(
    TARGETS js_generic_base.enclave
    EXPORT ccf
    DESTINATION lib
  )
elseif(COMPILE_TARGET STREQUAL "snp")
  add_library(
    js_generic_base.virtual STATIC
    ${CCF_DIR}/src/apps/js_generic/js_generic_base.cpp
  )
  add_san(js_generic_base.virtual)
  add_warning_checks(js_generic_base.virtual)
  target_link_libraries(js_generic_base.virtual PUBLIC ccf.virtual)
  target_compile_options(js_generic_base.virtual PRIVATE ${COMPILE_LIBCXX})
  target_compile_definitions(
    js_generic_base.virtual PUBLIC INSIDE_ENCLAVE VIRTUAL_ENCLAVE
                                   _LIBCPP_HAS_THREAD_API_PTHREAD PLATFORM_SNP
  )
  set_property(
    TARGET js_generic_base.virtual PROPERTY POSITION_INDEPENDENT_CODE ON
  )
  install(
    TARGETS js_generic_base.virtual
    EXPORT ccf
    DESTINATION lib
  )
elseif(COMPILE_TARGET STREQUAL "virtual")
  add_library(
    js_generic_base.virtual STATIC
    ${CCF_DIR}/src/apps/js_generic/js_generic_base.cpp
  )
  add_san(js_generic_base.virtual)
  add_warning_checks(js_generic_base.virtual)
  target_link_libraries(js_generic_base.virtual PUBLIC ccf.virtual)
  target_compile_options(js_generic_base.virtual PRIVATE ${COMPILE_LIBCXX})
  target_compile_definitions(
    js_openenclave.virtual
    PUBLIC INSIDE_ENCLAVE VIRTUAL_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD
           PLATFORM_VIRTUAL
  )
  set_property(
    TARGET js_generic_base.virtual PROPERTY POSITION_INDEPENDENT_CODE ON
  )
  install(
    TARGETS js_generic_base.virtual
    EXPORT ccf
    DESTINATION lib
  )
endif()
# SNIPPET_START: JS generic application
add_ccf_app(
  js_generic
  SRCS ${CCF_DIR}/src/apps/js_generic/js_generic.cpp
  LINK_LIBS_ENCLAVE js_generic_base.enclave js_openenclave.enclave
  LINK_LIBS_VIRTUAL js_generic_base.virtual js_openenclave.virtual INSTALL_LIBS
                    ON
)
sign_app_library(
  js_generic.enclave ${CCF_DIR}/src/apps/js_generic/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem INSTALL_LIBS ON
)
# SNIPPET_END: JS generic application

include(${CCF_DIR}/cmake/quictls.cmake)

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
    ${name} PRIVATE ${CCF_DIR}/src/clients/perf ${PARSED_ARGS_INCLUDE_DIRS}
  )

endfunction()

# Helper for building end-to-end function tests using the python infrastructure
function(add_e2e_test)
  cmake_parse_arguments(
    PARSE_ARGV 0 PARSED_ARGS ""
    "NAME;PYTHON_SCRIPT;LABEL;CURL_CLIENT;CONSENSUS;"
    "CONSTITUTION;ADDITIONAL_ARGS;CONFIGURATIONS;CONTAINER_NODES"
  )

  if(NOT PARSED_ARGS_CONSTITUTION)
    set(PARSED_ARGS_CONSTITUTION ${CCF_NETWORK_TEST_DEFAULT_CONSTITUTION})
  endif()

  if(BUILD_END_TO_END_TESTS)
    if(PROFILE_TESTS)
      set(PYTHON_WRAPPER
          py-spy
          record
          --format
          speedscope
          -o
          ${PARSED_ARGS_NAME}.trace
          --
          python3
      )
    else()
      set(PYTHON_WRAPPER ${PYTHON})
    endif()

    string(TOUPPER ${PARSED_ARGS_CONSENSUS} CONSENSUS)
    add_test(
      NAME ${PARSED_ARGS_NAME}
      COMMAND
        ${PYTHON_WRAPPER} ${PARSED_ARGS_PYTHON_SCRIPT} -b . --label
        ${PARSED_ARGS_NAME} ${CCF_NETWORK_TEST_ARGS} ${PARSED_ARGS_CONSTITUTION}
        --consensus ${CONSENSUS} ${PARSED_ARGS_ADDITIONAL_ARGS}
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

    if("${PARSED_ARGS_LABEL}" STREQUAL "partitions")
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1"
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
    if((${PARSED_ARGS_CONTAINER_NODES}) AND (LONG_TESTS))
      # Containerised nodes are only enabled with long tests
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY ENVIRONMENT "CONTAINER_NODES=ON"
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
  set(ENCLAVE_TYPE "")
  if("sgx" STREQUAL COMPILE_TARGET)
    set(TESTS_SUFFIX "${TESTS_SUFFIX}_sgx")
    set(ENCLAVE_TYPE "release")
  elseif("virtual" STREQUAL COMPILE_TARGET)
    set(TESTS_SUFFIX "${TESTS_SUFFIX}_virtual")
    set(ENCLAVE_TYPE "virtual")
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

  string(TOUPPER ${PARSED_ARGS_CONSENSUS} CONSENSUS)
  add_test(
    NAME "${PARSED_ARGS_NAME}${TESTS_SUFFIX}"
    COMMAND
      ${PYTHON} ${PARSED_ARGS_PYTHON_SCRIPT} -b . -c ${PARSED_ARGS_CLIENT_BIN}
      ${CCF_NETWORK_TEST_ARGS} --consensus ${CONSENSUS}
      ${PARSED_ARGS_CONSTITUTION} --write-tx-times ${VERIFICATION_ARG} --label
      ${LABEL_ARG} --snapshot-tx-interval 10000 ${PARSED_ARGS_ADDITIONAL_ARGS}
      -e ${ENCLAVE_TYPE} ${NODES}
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
