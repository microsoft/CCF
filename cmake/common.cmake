# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CMAKE_MODULE_PATH "${CCF_DIR}/cmake;${CMAKE_MODULE_PATH}")

set(default_build_type "RelWithDebInfo")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(
    STATUS
      "Setting build type to '${default_build_type}' as none was specified."
  )
  set(CMAKE_BUILD_TYPE
      "${default_build_type}"
      CACHE STRING "Choose the type of build." FORCE
  )
  set_property(
    CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel"
                                    "RelWithDebInfo"
  )
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

set(PYTHON unbuffer python3)

set(SERVICE_IDENTITY_CURVE_CHOICE
    "secp384r1"
    CACHE STRING
          "One of secp384r1, ed25519, secp256k1_mbedtls, secp256k1_bitcoin"
)
if(${SERVICE_IDENTITY_CURVE_CHOICE} STREQUAL "secp384r1")
  add_definitions(-DSERVICE_IDENTITY_CURVE_CHOICE_SECP384R1)
  set(DEFAULT_PARTICIPANTS_CURVE "secp384r1")
elseif(${SERVICE_IDENTITY_CURVE_CHOICE} STREQUAL "ed25519")
  add_definitions(-DSERVICE_IDENTITY_CURVE_CHOICE_ED25519)
  set(DEFAULT_PARTICIPANTS_CURVE "ed25519")
elseif(${SERVICE_IDENTITY_CURVE_CHOICE} STREQUAL "secp256k1_mbedtls")
  add_definitions(-DSERVICE_IDENTITY_CURVE_CHOICE_SECP256K1_MBEDTLS)
  set(DEFAULT_PARTICIPANTS_CURVE "secp256k1")
elseif(${SERVICE_IDENTITY_CURVE_CHOICE} STREQUAL "secp256k1_bitcoin")
  add_definitions(-DSERVICE_IDENTITY_CURVE_CHOICE_SECP256K1_BITCOIN)
  set(DEFAULT_PARTICIPANTS_CURVE "secp256k1")
else()
  message(
    FATAL_ERROR "Unsupported curve choice ${SERVICE_IDENTITY_CURVE_CHOICE}"
  )
endif()

set(DISTRIBUTE_PERF_TESTS
    ""
    CACHE
      STRING
      "Hosts to which performance tests should be distributed, for example -n x.x.x.x -n x.x.x.x -n x.x.x.x"
)

if(DISTRIBUTE_PERF_TESTS)
  separate_arguments(NODES UNIX_COMMAND ${DISTRIBUTE_PERF_TESTS})
else()
  unset(NODES)
endif()

option(COLORED_OUTPUT "Always produce ANSI-colored output (Clang only)." TRUE)

if(${COLORED_OUTPUT})
  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    add_compile_options(-fcolor-diagnostics)
  endif()
endif()

option(VERBOSE_LOGGING "Enable verbose logging" OFF)
set(TEST_HOST_LOGGING_LEVEL "info")
if(VERBOSE_LOGGING)
  add_definitions(-DVERBOSE_LOGGING)
  set(TEST_HOST_LOGGING_LEVEL "debug")
endif()

option(NO_STRICT_TLS_CIPHERSUITES
       "Disable strict list of valid TLS ciphersuites" OFF
)
if(NO_STRICT_TLS_CIPHERSUITES)
  add_definitions(-DNO_STRICT_TLS_CIPHERSUITES)
endif()

option(USE_NULL_ENCRYPTOR "Turn off encryption of ledger updates - debug only"
       OFF
)
if(USE_NULL_ENCRYPTOR)
  add_definitions(-DUSE_NULL_ENCRYPTOR)
endif()

option(SAN "Enable Address and Undefined Behavior Sanitizers" OFF)
option(DISABLE_QUOTE_VERIFICATION "Disable quote verification" OFF)
option(BUILD_END_TO_END_TESTS "Build end to end tests" ON)
option(COVERAGE "Enable coverage mapping" OFF)

option(PBFT "Enable PBFT" OFF)
if(PBFT)
  add_definitions(-DPBFT)
  add_definitions(
    -DUSE_NULL_ENCRYPTOR
  ) # for now do not encrypt the ledger as the current implementation does not
    # work for PBFT
  set(PBFT_BUILD_ENCLAVE TRUE)
  set(PBFT_BUILD_HOST TRUE)
  set(PBFT_USE_LIBC TRUE)
endif()

option(DEBUG_CONFIG "Enable non-production options options to aid debugging"
       OFF
)
if(DEBUG_CONFIG)
  add_definitions(-DDEBUG_CONFIG)
endif()

option(USE_NLJSON_KV_SERIALISER "Use nlohmann JSON as the KV serialiser" OFF)
if(USE_NLJSON_KV_SERIALISER)
  add_definitions(-DUSE_NLJSON_KV_SERIALISER)
endif()

enable_language(ASM)

set(CCF_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

add_custom_command(
  OUTPUT ${CCF_GENERATED_DIR}/frame_generated.h
  COMMAND flatc -o "${CCF_GENERATED_DIR}" --cpp ${CCF_DIR}/src/kv/frame.fbs
  COMMAND flatc -o "${CCF_GENERATED_DIR}" --python ${CCF_DIR}/src/kv/frame.fbs
  DEPENDS ${CCF_DIR}/src/kv/frame.fbs
)

install(FILES ${CCF_GENERATED_DIR}/frame_generated.h DESTINATION generated)

include_directories(${CCF_DIR}/src ${CCF_GENERATED_DIR})

include_directories(
  SYSTEM ${CCF_DIR}/3rdparty ${CCF_DIR}/3rdparty/hacl-star
  ${CCF_DIR}/3rdparty/msgpack-c ${CCF_DIR}/3rdparty/flatbuffers/include
)

set(TARGET
    "sgx;virtual"
    CACHE STRING "One of sgx, virtual, or 'sgx;virtual'"
)

find_package(MbedTLS REQUIRED)

set(CLIENT_MBEDTLS_INCLUDE_DIR "${MBEDTLS_INCLUDE_DIRS}")
set(CLIENT_MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARIES}")

find_package(OpenEnclave CONFIG REQUIRED)
# As well as pulling in openenclave:: targets, this sets variables which can be
# used for our edge cases (eg - for virtual libraries). These do not follow the
# standard naming patterns, for example use OE_INCLUDEDIR rather than
# OpenEnclave_INCLUDE_DIRS

add_custom_command(
  COMMAND openenclave::oeedger8r ${CCF_DIR}/edl/ccf.edl --trusted --trusted-dir
          ${CCF_GENERATED_DIR} --untrusted --untrusted-dir ${CCF_GENERATED_DIR}
  COMMAND mv ${CCF_GENERATED_DIR}/ccf_t.c ${CCF_GENERATED_DIR}/ccf_t.cpp
  COMMAND mv ${CCF_GENERATED_DIR}/ccf_u.c ${CCF_GENERATED_DIR}/ccf_u.cpp
  DEPENDS ${CCF_DIR}/edl/ccf.edl
  OUTPUT ${CCF_GENERATED_DIR}/ccf_t.cpp ${CCF_GENERATED_DIR}/ccf_u.cpp
  COMMENT "Generating code from EDL, and renaming to .cpp"
)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccf_app.cmake)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccf_app.cmake DESTINATION cmake)

# Copy utilities from tests directory
set(CCF_UTILITIES tests.sh keygenerator.sh cimetrics_env.sh
                  upload_pico_metrics.py scurl.sh
)
foreach(UTILITY ${CCF_UTILITIES})
  configure_file(
    ${CCF_DIR}/tests/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
endforeach()

# Install specific utilities
install(PROGRAMS ${CCF_DIR}/tests/scurl.sh ${CCF_DIR}/tests/keygenerator.sh
        DESTINATION bin
)

if("sgx" IN_LIST TARGET)
  # If OE was built with LINK_SGX=1, then we also need to link SGX
  if(OE_SGX)
    message(STATUS "Linking SGX")
    set(SGX_LIBS sgx_enclave_common sgx_dcap_ql sgx_urts)

    if(NOT DISABLE_QUOTE_VERIFICATION)
      set(QUOTES_ENABLED ON)
    else()
      set(TEST_IGNORE_QUOTE "--ignore-quote")
    endif()
  else()
    set(TEST_IGNORE_QUOTE "--ignore-quote")
  endif()
else()
  set(TEST_ENCLAVE_TYPE -e virtual)
endif()

# Test-only option to enable extensive tests
option(EXTENSIVE_TESTS "Enable extensive tests" OFF)
if(EXTENSIVE_TESTS)
  set(RECOVERY_ARGS --recovery 5 --msgs-per-recovery 10)
else()
  set(RECOVERY_ARGS --recovery 2 --msgs-per-recovery 5)
endif()

# Lua module
set(LUA_DIR ${CCF_DIR}/3rdparty/lua)
set(LUA_SOURCES
    ${LUA_DIR}/lapi.c
    ${LUA_DIR}/lauxlib.c
    ${LUA_DIR}/lbaselib.c
    ${LUA_DIR}/lcode.c
    ${LUA_DIR}/lcorolib.c
    ${LUA_DIR}/lctype.c
    ${LUA_DIR}/ldebug.c
    ${LUA_DIR}/ldo.c
    ${LUA_DIR}/ldump.c
    ${LUA_DIR}/lfunc.c
    ${LUA_DIR}/lgc.c
    ${LUA_DIR}/llex.c
    ${LUA_DIR}/lmathlib.c
    ${LUA_DIR}/lmem.c
    ${LUA_DIR}/lobject.c
    ${LUA_DIR}/lopcodes.c
    ${LUA_DIR}/lparser.c
    ${LUA_DIR}/lstate.c
    ${LUA_DIR}/lstring.c
    ${LUA_DIR}/lstrlib.c
    ${LUA_DIR}/ltable.c
    ${LUA_DIR}/ltablib.c
    ${LUA_DIR}/ltm.c
    ${LUA_DIR}/lundump.c
    ${LUA_DIR}/lutf8lib.c
    ${LUA_DIR}/lvm.c
    ${LUA_DIR}/lzio.c
)

set(HTTP_PARSER_SOURCES ${CCF_DIR}/3rdparty/http-parser/http_parser.c)

find_library(CRYPTO_LIBRARY crypto)

function(add_enclave_library_c name files)
  add_library(${name} STATIC ${files})
  target_compile_options(${name} PRIVATE -nostdinc)
  target_link_libraries(${name} PRIVATE openenclave::oelibc)
  set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)
endfunction()

include(${CCF_DIR}/cmake/crypto.cmake)
include(${CCF_DIR}/cmake/secp256k1.cmake)
include(${CCF_DIR}/cmake/quickjs.cmake)
include(${CCF_DIR}/cmake/sss.cmake)

find_package(CURL REQUIRED)

# Unit test wrapper
function(add_unit_test name)
  add_executable(${name} ${CCF_DIR}/src/enclave/thread_local.cpp ${ARGN})
  target_compile_options(${name} PRIVATE -stdlib=libc++)
  target_include_directories(${name} PRIVATE src ${CCFCRYPTO_INC})
  enable_coverage(${name})
  target_link_libraries(
    ${name} PRIVATE -stdlib=libc++ -lc++ -lc++abi ccfcrypto.host
  )
  add_dependencies(${name} flatbuffers)
  use_client_mbedtls(${name})
  add_san(${name})

  add_test(NAME ${name} COMMAND ${CCF_DIR}/tests/unit_test_wrapper.sh ${name})
  set_property(TEST ${name} APPEND PROPERTY LABELS unit_test)
endfunction()

if("sgx" IN_LIST TARGET)
  # Host Executable
  add_executable(
    cchost ${CCF_DIR}/src/host/main.cpp ${CCF_GENERATED_DIR}/ccf_u.cpp
  )
  use_client_mbedtls(cchost)
  target_include_directories(cchost PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  add_san(cchost)

  target_link_libraries(
    cchost
    PRIVATE uv
            ${SGX_LIBS}
            ${CRYPTO_LIBRARY}
            ${CMAKE_DL_LIBS}
            ${CMAKE_THREAD_LIBS_INIT}
            openenclave::oehostapp
            ccfcrypto.host
            evercrypt.host
            CURL::libcurl
  )
  add_dependencies(cchost flatbuffers)
  enable_quote_code(cchost)

  install(TARGETS cchost DESTINATION bin)
endif()

if("virtual" IN_LIST TARGET)
  # Virtual Host Executable
  add_executable(cchost.virtual ${CCF_DIR}/src/host/main.cpp)
  use_client_mbedtls(cchost.virtual)
  target_compile_definitions(cchost.virtual PRIVATE -DVIRTUAL_ENCLAVE)
  target_compile_options(cchost.virtual PRIVATE -stdlib=libc++)
  target_include_directories(
    cchost.virtual PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OE_INCLUDEDIR}
  )
  add_san(cchost.virtual)
  enable_coverage(cchost.virtual)
  target_link_libraries(
    cchost.virtual
    PRIVATE uv
            ${CRYPTO_LIBRARY}
            ${CMAKE_DL_LIBS}
            ${CMAKE_THREAD_LIBS_INIT}
            -lc++
            -lc++abi
            -stdlib=libc++
            ccfcrypto.host
            evercrypt.host
            CURL::libcurl
  )
  add_dependencies(cchost.virtual flatbuffers)

  install(TARGETS cchost.virtual DESTINATION bin)
endif()

# Perf scenario executable
add_executable(
  scenario_perf_client ${CCF_DIR}/samples/perf_client/scenario_perf_client.cpp
)
use_client_mbedtls(scenario_perf_client)
target_link_libraries(
  scenario_perf_client PRIVATE ${CMAKE_THREAD_LIBS_INIT} secp256k1.host
                               http_parser.host
)
add_dependencies(scenario_perf_client flatbuffers)

# Lua for host and enclave
add_enclave_library_c(lua.enclave "${LUA_SOURCES}")
target_compile_options(lua.enclave PRIVATE -Wno-string-plus-int)
target_compile_definitions(lua.enclave PRIVATE NO_IO)
install(
  TARGETS lua.enclave
  EXPORT ccf
  DESTINATION lib
)

add_library(lua.host STATIC ${LUA_SOURCES})
target_compile_options(lua.host PRIVATE -Wno-string-plus-int)
target_compile_definitions(lua.host PRIVATE NO_IO)
set_property(TARGET lua.host PROPERTY POSITION_INDEPENDENT_CODE ON)
install(
  TARGETS lua.host
  EXPORT ccf
  DESTINATION lib
)

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

# Common test args for Python scripts starting up CCF networks
if(PBFT)
  set(CONSENSUS_ARG "pbft")
else()
  set(CONSENSUS_ARG "raft")
endif()

if((NOT CMAKE_BUILD_TYPE STREQUAL "Debug") AND NOT PBFT)
  set(WORKER_THREADS 2)
else()
  set(WORKER_THREADS 0)
endif()
message(STATUS "Setting default WORKER_THREADS to '${WORKER_THREADS}'")

set(CCF_NETWORK_TEST_ARGS
    ${TEST_IGNORE_QUOTE}
    ${TEST_ENCLAVE_TYPE}
    -l
    ${TEST_HOST_LOGGING_LEVEL}
    -g
    ${CCF_DIR}/src/runtime_config/gov.lua
    --consensus
    ${CONSENSUS_ARG}
    --worker_threads
    ${WORKER_THREADS}
    --default-curve
    ${DEFAULT_PARTICIPANTS_CURVE}
)

# SNIPPET_START: Lua generic application
add_ccf_app(luageneric SRCS ${CCF_DIR}/src/apps/luageneric/luageneric.cpp)
sign_app_library(
  luageneric.enclave ${CCF_DIR}/src/apps/luageneric/oe_sign.conf
  ${CCF_DIR}/src/apps/sample_key.pem
)
# SNIPPET_END: Lua generic application

add_ccf_app(
  jsgeneric
  SRCS ${CCF_DIR}/src/apps/jsgeneric/jsgeneric.cpp
  LINK_LIBS_ENCLAVE quickjs.enclave -lgcc
  LINK_LIBS_VIRTUAL quickjs.host
)
sign_app_library(
  jsgeneric.enclave ${CCF_DIR}/src/apps/jsgeneric/oe_sign.conf
  ${CCF_DIR}/src/apps/sample_key.pem
)

# Samples

# Helper for building clients inheriting from perf_client
function(add_client_exe name)

  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  add_executable(${name} ${PARSED_ARGS_SRCS})

  target_link_libraries(${name} PRIVATE ${CMAKE_THREAD_LIBS_INIT})

  add_dependencies(${name} flatbuffers)
  target_include_directories(
    ${name} PRIVATE ${CCF_DIR}/samples/perf_client ${PARSED_ARGS_INCLUDE_DIRS}
  )

  use_client_mbedtls(${name})

endfunction()

# Helper for building end-to-end function tests using the python infrastructure
function(add_e2e_test)
  cmake_parse_arguments(
    PARSE_ARGV 0 PARSED_ARGS "" "NAME;PYTHON_SCRIPT;IS_SUITE;CURL_CLIENT"
    "ADDITIONAL_ARGS"
  )

  if(BUILD_END_TO_END_TESTS)
    add_test(
      NAME ${PARSED_ARGS_NAME}
      COMMAND
        ${PYTHON} ${PARSED_ARGS_PYTHON_SCRIPT} -b . --label ${PARSED_ARGS_NAME}
        ${CCF_NETWORK_TEST_ARGS} ${PARSED_ARGS_ADDITIONAL_ARGS}
    )

    # Make python test client framework importable
    set_property(
      TEST ${PARSED_ARGS_NAME} APPEND
      PROPERTY
        ENVIRONMENT
        "PYTHONPATH=${CCF_DIR}/tests:${CCF_GENERATED_DIR}:$ENV{PYTHONPATH}"
    )
    if(${PARSED_ARGS_IS_SUITE})
      set_property(TEST ${PARSED_ARGS_NAME} APPEND PROPERTY LABELS suite)
    else()
      set_property(TEST ${PARSED_ARGS_NAME} APPEND PROPERTY LABELS end_to_end)
    endif()

    if(${PARSED_ARGS_CURL_CLIENT})
      set_property(
        TEST ${PARSED_ARGS_NAME} APPEND PROPERTY ENVIRONMENT "CURL_CLIENT=ON"
      )
    endif()
  endif()
endfunction()

# Helper for building end-to-end perf tests using the python infrastucture
function(add_perf_test)

  cmake_parse_arguments(
    PARSE_ARGV 0 PARSED_ARGS ""
    "NAME;PYTHON_SCRIPT;CLIENT_BIN;VERIFICATION_FILE;LABEL;" "ADDITIONAL_ARGS"
  )

  if(PARSED_ARGS_VERIFICATION_FILE)
    set(VERIFICATION_ARG "--verify ${PARSED_ARGS_VERIFICATION_FILE}")
  else()
    unset(VERIFICATION_ARG)
  endif()

  if(PARSED_ARGS_LABEL)
    set(LABEL_ARG "${PARSED_ARGS_LABEL}_${TESTS_SUFFIX}^")
  else()
    set(LABEL_ARG "${PARSED_ARGS_NAME}_${TESTS_SUFFIX}^")
  endif()

  add_test(
    NAME ${PARSED_ARGS_NAME}
    COMMAND
      ${PYTHON} ${PARSED_ARGS_PYTHON_SCRIPT} -b . -c ${PARSED_ARGS_CLIENT_BIN}
      ${CCF_NETWORK_TEST_ARGS} --write-tx-times ${VERIFICATION_ARG} --label
      ${LABEL_ARG} ${PARSED_ARGS_ADDITIONAL_ARGS} ${RELAX_COMMIT_TARGET}
      ${NODES}
  )

  # Make python test client framework importable
  set_property(
    TEST ${PARSED_ARGS_NAME} APPEND
    PROPERTY
      ENVIRONMENT
      "PYTHONPATH=${CCF_DIR}/tests:${CMAKE_CURRENT_BINARY_DIR}:$ENV{PYTHONPATH}"
  )
  set_property(TEST ${PARSED_ARGS_NAME} APPEND PROPERTY LABELS perf)
endfunction()

# Picobench wrapper
function(add_picobench name)
  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  add_executable(${name} ${PARSED_ARGS_SRCS})

  target_include_directories(${name} PRIVATE src ${PARSED_ARGS_INCLUDE_DIRS})

  add_dependencies(${name} flatbuffers)

  target_link_libraries(
    ${name} PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${PARSED_ARGS_LINK_LIBS}
  )

  # -Wall -Werror catches a number of warnings in picobench
  target_include_directories(${name} SYSTEM PRIVATE 3rdparty)

  add_test(
    NAME ${name}
    COMMAND
      bash -c
      "$<TARGET_FILE:${name}> --samples=1000 --out-fmt=csv --output=${name}.csv && cat ${name}.csv"
  )

  use_client_mbedtls(${name})

  set_property(TEST ${name} PROPERTY LABELS benchmark)
endfunction()
