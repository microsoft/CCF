# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CMAKE_MODULE_PATH "${CCF_DIR}/cmake;${CMAKE_MODULE_PATH}")

set(MSGPACK_INCLUDE_DIR ${CCF_DIR}/3rdparty/msgpack-c)
set(FLATBUFFERS_INCLUDE_DIR ${CCF_DIR}/3rdparty/flatbuffers/include)

set(default_build_type "RelWithDebInfo")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
    set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

set(PYTHON unbuffer python3)

separate_arguments(COVERAGE_FLAGS UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping")
separate_arguments(COVERAGE_LINK UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping")

function(enable_coverage name)
  if (COVERAGE)
    target_compile_options(${name} PRIVATE ${COVERAGE_FLAGS})
    target_link_libraries(${name} PRIVATE ${COVERAGE_LINK})
  endif()
endfunction()

set(SERVICE_IDENTITY_CURVE_CHOICE "secp384r1" CACHE STRING "One of secp384r1, ed25519, secp256k1_mbedtls, secp256k1_bitcoin")
if (${SERVICE_IDENTITY_CURVE_CHOICE} STREQUAL "secp384r1")
  add_definitions(-DSERVICE_IDENTITY_CURVE_CHOICE_SECP384R1)
  set(DEFAULT_PARTICIPANTS_CURVE "secp384r1")
elseif (${SERVICE_IDENTITY_CURVE_CHOICE} STREQUAL "ed25519")
  add_definitions(-DSERVICE_IDENTITY_CURVE_CHOICE_ED25519)
  set(DEFAULT_PARTICIPANTS_CURVE "ed25519")
elseif (${SERVICE_IDENTITY_CURVE_CHOICE} STREQUAL "secp256k1_mbedtls")
  add_definitions(-DSERVICE_IDENTITY_CURVE_CHOICE_SECP256K1_MBEDTLS)
  set(DEFAULT_PARTICIPANTS_CURVE "secp256k1")
elseif (${SERVICE_IDENTITY_CURVE_CHOICE} STREQUAL "secp256k1_bitcoin")
  add_definitions(-DSERVICE_IDENTITY_CURVE_CHOICE_SECP256K1_BITCOIN)
  set(DEFAULT_PARTICIPANTS_CURVE "secp256k1")
else ()
  message(FATAL_ERROR "Unsupported curve choice ${SERVICE_IDENTITY_CURVE_CHOICE}")
endif ()

option (COLORED_OUTPUT "Always produce ANSI-colored output (Clang only)." TRUE)

if (${COLORED_OUTPUT})
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       add_compile_options (-fcolor-diagnostics)
    endif ()
endif ()

option(VERBOSE_LOGGING "Enable verbose logging" OFF)
set(TEST_HOST_LOGGING_LEVEL "info")
if(VERBOSE_LOGGING)
  add_definitions(-DVERBOSE_LOGGING)
  set(TEST_HOST_LOGGING_LEVEL "debug")
endif()

option(NO_STRICT_TLS_CIPHERSUITES "Disable strict list of valid TLS ciphersuites" OFF)
if(NO_STRICT_TLS_CIPHERSUITES)
  add_definitions(-DNO_STRICT_TLS_CIPHERSUITES)
endif()

option(USE_NULL_ENCRYPTOR "Turn off encryption of ledger updates - debug only" OFF)
if (USE_NULL_ENCRYPTOR)
  add_definitions(-DUSE_NULL_ENCRYPTOR)
endif()

option(HTTP "Enable HTTP Support" OFF)
if (HTTP)
  add_definitions(-DHTTP)
endif()

option(SAN "Enable Address and Undefined Behavior Sanitizers" OFF)
option(DISABLE_QUOTE_VERIFICATION "Disable quote verification" OFF)
option(BUILD_END_TO_END_TESTS "Build end to end tests" ON)
option(COVERAGE "Enable coverage mapping" OFF)

option(PBFT "Enable PBFT" OFF)
if (PBFT)
  add_definitions(-DPBFT)
  add_definitions(-DUSE_NULL_ENCRYPTOR) # for now do not encrypt the ledger as the current implementation does not work for PBFT
  set(PBFT_BUILD_ENCLAVE TRUE)
  set(PBFT_BUILD_HOST TRUE)
  set(PBFT_USE_LIBC TRUE)
endif()

option(DEBUG_CONFIG "Enable non-production options options to aid debugging" OFF)
if(DEBUG_CONFIG)
  add_definitions(-DDEBUG_CONFIG)
endif()

option(USE_NLJSON_KV_SERIALISER "Use nlohmann JSON as the KV serialiser" OFF)
if (USE_NLJSON_KV_SERIALISER)
  add_definitions(-DUSE_NLJSON_KV_SERIALISER)
endif()

enable_language(ASM)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/frame_generated.h
    COMMAND flatc --cpp ${CCF_DIR}/src/kv/frame.fbs
    COMMAND flatc --python ${CCF_DIR}/src/kv/frame.fbs
    DEPENDS ${CCF_DIR}/src/kv/frame.fbs
)

add_custom_target(flatbuffers ALL
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/frame_generated.h
)

include_directories(
  ${CCF_DIR}/src
)

include_directories(
  SYSTEM
  ${CCF_DIR}/3rdparty
  ${CCF_DIR}/3rdparty/evercrypt-msr
  ${MSGPACK_INCLUDE_DIR}
  ${FLATBUFFERS_INCLUDE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

set(TARGET "sgx;virtual" CACHE STRING "One of sgx, virtual, or 'sgx;virtual'")

set(OE_PREFIX "/opt/openenclave" CACHE PATH "Path to Open Enclave install")
message(STATUS "Open Enclave prefix set to ${OE_PREFIX}")

find_package(MbedTLS REQUIRED)

set(CLIENT_MBEDTLS_INCLUDE_DIR "${MBEDTLS_INCLUDE_DIRS}")
set(CLIENT_MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARIES}")

set(OE_INCLUDE_DIR "${OE_PREFIX}/include")
set(OE_LIB_DIR "${OE_PREFIX}/lib/openenclave")
set(OE_BIN_DIR "${OE_PREFIX}/bin")

set(OE_TP_INCLUDE_DIR   "${OE_INCLUDE_DIR}/openenclave/3rdparty")
set(OE_LIBC_INCLUDE_DIR   "${OE_INCLUDE_DIR}/openenclave/3rdparty/libc")
set(OE_LIBCXX_INCLUDE_DIR "${OE_INCLUDE_DIR}/openenclave/3rdparty/libcxx")

set(OESIGN "${OE_BIN_DIR}/oesign")
set(OEGEN "${OE_BIN_DIR}/oeedger8r")


add_custom_command(
    COMMAND ${OEGEN} ${CCF_DIR}/src/edl/ccf.edl --trusted --trusted-dir ${CMAKE_CURRENT_BINARY_DIR} --untrusted --untrusted-dir ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND mv ${CMAKE_CURRENT_BINARY_DIR}/ccf_t.c ${CMAKE_CURRENT_BINARY_DIR}/ccf_t.cpp
    COMMAND mv ${CMAKE_CURRENT_BINARY_DIR}/ccf_u.c ${CMAKE_CURRENT_BINARY_DIR}/ccf_u.cpp
    DEPENDS ${CCF_DIR}/src/edl/ccf.edl
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/ccf_t.cpp ${CMAKE_CURRENT_BINARY_DIR}/ccf_u.cpp
    COMMENT "Generating code from EDL, and renaming to .cpp"
)

# Copy utilities from tests directory
set(CCF_UTILITIES tests.sh keygenerator.sh cimetrics_env.sh upload_pico_metrics.py scurl.sh)
foreach(UTILITY ${CCF_UTILITIES})
  configure_file(${CCF_DIR}/tests/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
endforeach()

if("sgx" IN_LIST TARGET)
  # If OE was built with LINK_SGX=1, then we also need to link SGX
  execute_process(COMMAND "ldd" ${OESIGN}
                  COMMAND "grep" "-c" "sgx"
                  OUTPUT_QUIET
                  RESULT_VARIABLE OE_NO_SGX)

  if(NOT OE_NO_SGX)
    message(STATUS "Linking SGX")
    set(SGX_LIBS
      sgx_enclave_common
      sgx_dcap_ql
      sgx_urts
    )

    if (NOT DISABLE_QUOTE_VERIFICATION)
      set(QUOTES_ENABLED ON)
    else()
      set(TEST_IGNORE_QUOTE "--ignore-quote")
    endif()
  else()
    set(TEST_IGNORE_QUOTE "--ignore-quote")
  endif()
else()
  set(TEST_ENCLAVE_TYPE
    -e virtual)
endif()

# Test-only option to enable extensive tests
option(EXTENSIVE_TESTS "Enable extensive tests" OFF)
if (EXTENSIVE_TESTS)
  set(RECOVERY_ARGS
    --recovery 5
    --msgs-per-recovery 10)
else()
  set(RECOVERY_ARGS
    --recovery 2
    --msgs-per-recovery 5)
endif()

# Lua module
set(LUA_DIR
  ${CCF_DIR}/3rdparty/lua)
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
  ${LUA_DIR}/lzio.c)

set(HTTP_PARSER_SOURCES
  ${CCF_DIR}/3rdparty/http-parser/http_parser.c)

set(OE_MBEDTLS_LIBRARIES
  "${OE_LIB_DIR}/enclave/libmbedtls.a"
  "${OE_LIB_DIR}/enclave/libmbedx509.a"
  "${OE_LIB_DIR}/enclave/libmbedcrypto.a"
)

find_library(CRYPTO_LIBRARY crypto)

set(OE_ENCLAVE_MBEDTLS "${OE_LIB_DIR}/enclave/libmbedtls.a")
set(OE_ENCLAVE_MBEDX509 "${OE_LIB_DIR}/enclave/libmbedx509.a")
set(OE_ENCLAVE_MBEDCRYPTO "${OE_LIB_DIR}/enclave/libmbedcrypto.a")
set(OE_ENCLAVE_CRYPTOMBED "${OE_LIB_DIR}/enclave/liboecryptombed.a")
set(OE_ENCLAVE_LIBRARY "${OE_LIB_DIR}/enclave/liboeenclave.a")
set(OE_ENCLAVE_CORE "${OE_LIB_DIR}/enclave/liboecore.a")
set(OE_ENCLAVE_SYSCALL "${OE_LIB_DIR}/enclave/liboesyscall.a")
set(OE_ENCLAVE_LIBC "${OE_LIB_DIR}/enclave/liboelibc.a")
set(OE_ENCLAVE_LIBCXX "${OE_LIB_DIR}/enclave/liboelibcxx.a")
set(OE_HOST_LIBRARY "${OE_LIB_DIR}/host/liboehost.a")

# The OE libraries must be listed in a specific order. Issue #887 on github
set(ENCLAVE_LIBS
  ccfcrypto.enclave
  evercrypt.enclave
  lua.enclave
  ${OE_ENCLAVE_LIBRARY}
  ${OE_ENCLAVE_CRYPTOMBED}
  ${OE_ENCLAVE_MBEDCRYPTO}
  ${OE_ENCLAVE_MBEDX509}
  ${OE_ENCLAVE_MBEDTLS}
  ${ENCLAVE_MBEDTLS_LIBRARIES}
  ${OE_ENCLAVE_LIBCXX}
  ${OE_ENCLAVE_LIBC}
  ${OE_ENCLAVE_SYSCALL}
  ${OE_ENCLAVE_CORE}
  secp256k1.enclave
)

set(ENCLAVE_FILES
  ${CCF_DIR}/src/enclave/main.cpp
)

function(enable_quote_code name)
  if (QUOTES_ENABLED)
    target_compile_definitions(${name} PRIVATE -DGET_QUOTE)
  endif()
endfunction()

function(add_enclave_library_c name files)
  add_library(${name} STATIC
    ${files})
  target_compile_options(${name} PRIVATE
    -nostdinc
    -U__linux__)
  target_include_directories(${name} SYSTEM PRIVATE
    ${OE_LIBC_INCLUDE_DIR}
    )
  set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)
  enable_quote_code(${name})
endfunction()

function(use_client_mbedtls name)
  target_include_directories(${name} PRIVATE ${CLIENT_MBEDTLS_INCLUDE_DIR})
  target_link_libraries(${name} PRIVATE ${CLIENT_MBEDTLS_LIBRARIES})
endfunction()

function(use_oe_mbedtls name)
  target_include_directories(${name} PRIVATE ${OE_TP_INCLUDE_DIR})
  target_link_libraries(${name} PRIVATE ${OE_MBEDTLS_LIBRARIES})
endfunction()

function(add_san name)
  if(SAN)
    target_compile_options(${name} PRIVATE
      -fsanitize=undefined,address -fno-omit-frame-pointer -fno-sanitize-recover=all
      -fno-sanitize=function -fsanitize-blacklist=${CCF_DIR}/src/ubsan.blacklist
    )
    target_link_libraries(${name} PRIVATE
      -fsanitize=undefined,address -fno-omit-frame-pointer -fno-sanitize-recover=all
      -fno-sanitize=function -fsanitize-blacklist=${CCF_DIR}/src/ubsan.blacklist
    )
  endif()
endfunction()

function(sign_app_library name app_oe_conf_path enclave_sign_key_path)
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.signed
    COMMAND ${OESIGN} sign
      -e ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so
      -c ${app_oe_conf_path}
      -k ${enclave_sign_key_path}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so
      ${app_oe_conf_path}
      ${enclave_sign_key_path}
  )

  add_custom_target(${name}_signed ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.signed
  )
endfunction()

include(${CCF_DIR}/cmake/crypto.cmake)
include(${CCF_DIR}/cmake/secp256k1.cmake)

find_package(CURL REQUIRED)

function(create_patched_enclave_lib name app_oe_conf_path enclave_sign_key_path)
  set(patched_name ${name}.patched)
  set(patched_lib_name lib${patched_name}.so)
  add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${patched_lib_name}
      COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so ${CMAKE_CURRENT_BINARY_DIR}/${patched_lib_name}
      COMMAND PYTHONPATH=${CCF_DIR}/tests:$ENV{PYTHONPATH} python3 patch_binary.py -p ${CMAKE_CURRENT_BINARY_DIR}/${patched_lib_name}
      WORKING_DIRECTORY ${CCF_DIR}/tests
      DEPENDS ${name}
  )
  sign_app_library(${patched_name} ${app_oe_conf_path} ${enclave_sign_key_path})
endfunction()

## Enclave library wrapper
function(add_enclave_lib name app_oe_conf_path enclave_sign_key_path)

  cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS
    ""
    ""
    "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  if("sgx" IN_LIST TARGET)
    add_library(${name} SHARED
      ${ENCLAVE_FILES}
      ${PARSED_ARGS_SRCS}
      ${CMAKE_CURRENT_BINARY_DIR}/ccf_t.cpp
    )

    target_compile_definitions(${name} PRIVATE
      INSIDE_ENCLAVE
      _LIBCPP_HAS_THREAD_API_PTHREAD
    )
    # Not setting -nostdinc in order to pick up compiler specific xmmintrin.h.
    target_compile_options(${name} PRIVATE
      -nostdinc++
      -U__linux__
    )
    target_include_directories(${name} SYSTEM PRIVATE
      ${OE_INCLUDE_DIR}
      ${OE_LIBCXX_INCLUDE_DIR}
      ${OE_LIBC_INCLUDE_DIR}
      ${OE_TP_INCLUDE_DIR}
      ${PARSED_ARGS_INCLUDE_DIRS}
      ${EVERCRYPT_INC}
      ${CMAKE_CURRENT_BINARY_DIR}
    )
    add_dependencies(${name} flatbuffers)

    if (PBFT)
      target_link_libraries(${name} PRIVATE
        -Wl,--allow-multiple-definition #TODO(#important): This is unfortunate
        libbyz.enclave
      )
    endif()
    target_link_libraries(${name} PRIVATE
      -nostdlib -nodefaultlibs -nostartfiles
      -Wl,--no-undefined
      -Wl,-Bstatic,-Bsymbolic,--export-dynamic,-pie
      ${PARSED_ARGS_LINK_LIBS}
      ${ENCLAVE_LIBS}
      http_parser.enclave
    )
    set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)
    sign_app_library(${name} ${app_oe_conf_path} ${enclave_sign_key_path})
    enable_quote_code(${name})
    if (${name} STREQUAL "loggingenc")
        create_patched_enclave_lib(${name} ${app_oe_conf_path} ${enclave_sign_key_path})
    endif()
  endif()

  if("virtual" IN_LIST TARGET)
    ## Build a virtual enclave, loaded as a shared library without OE
    set(virt_name ${name}.virtual)
    add_library(${virt_name} SHARED
      ${ENCLAVE_FILES}
      ${PARSED_ARGS_SRCS}
      ${CMAKE_CURRENT_BINARY_DIR}/ccf_t.cpp
    )
    add_san(${virt_name})
    target_compile_definitions(${virt_name} PRIVATE
      INSIDE_ENCLAVE
      VIRTUAL_ENCLAVE
    )
    target_compile_options(${virt_name} PRIVATE
      -stdlib=libc++)
    target_include_directories(${virt_name} SYSTEM PRIVATE
      ${PARSED_ARGS_INCLUDE_DIRS}
      ${CCFCRYPTO_INC}
      ${EVERCRYPT_INC}
      ${OE_INCLUDE_DIR}
      ${CMAKE_CURRENT_BINARY_DIR}
    )
    add_dependencies(${virt_name} flatbuffers)

    if (PBFT)
      target_link_libraries(${virt_name} PRIVATE
        -Wl,--allow-multiple-definition #TODO(#important): This is unfortunate
        libbyz.host
      )
    endif()
    target_link_libraries(${virt_name} PRIVATE
      ${PARSED_ARGS_LINK_LIBS}
      -stdlib=libc++
      -lc++
      -lc++abi
      ccfcrypto.host
      evercrypt.host
      lua.host
      ${CMAKE_THREAD_LIBS_INIT}
      secp256k1.host
      http_parser.host
    )
    enable_coverage(${virt_name})
    use_client_mbedtls(${virt_name})
    set_property(TARGET ${virt_name} PROPERTY POSITION_INDEPENDENT_CODE ON)
  endif()
endfunction()

## Unit test wrapper
function(add_unit_test name)
  add_executable(${name}
    ${ARGN})
    target_compile_options(${name} PRIVATE -stdlib=libc++)
  target_include_directories(${name} PRIVATE
    src
    ${CCFCRYPTO_INC})
  enable_coverage(${name})
  target_link_libraries(${name} PRIVATE
      -stdlib=libc++
      -lc++
      -lc++abi
      ccfcrypto.host)
  add_dependencies(${name} flatbuffers)
  use_client_mbedtls(${name})
  add_san(${name})

  add_test(
    NAME ${name}
    COMMAND ${CCF_DIR}/tests/unit_test_wrapper.sh ${name}
  )
  set_property(
    TEST ${name}
    APPEND
    PROPERTY
      LABELS unit_test
  )
endfunction()

if("sgx" IN_LIST TARGET)
  # Host Executable
  add_executable(cchost
    ${CCF_DIR}/src/host/main.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/ccf_u.cpp)
  use_client_mbedtls(cchost)
  target_include_directories(cchost PRIVATE
    ${OE_INCLUDE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
  )
  add_san(cchost)

  target_link_libraries(cchost PRIVATE
    uv
    ${OE_HOST_LIBRARY}
    ${SGX_LIBS}
    ${CRYPTO_LIBRARY}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT}
    ccfcrypto.host
    evercrypt.host
    CURL::libcurl
  )
  add_dependencies(cchost flatbuffers)
  enable_quote_code(cchost)
endif()

if("virtual" IN_LIST TARGET)
  # Virtual Host Executable
  add_executable(cchost.virtual
    ${CCF_DIR}/src/host/main.cpp)
  use_client_mbedtls(cchost.virtual)
  target_compile_definitions(cchost.virtual PRIVATE -DVIRTUAL_ENCLAVE)
  target_compile_options(cchost.virtual PRIVATE -stdlib=libc++)
  target_include_directories(cchost.virtual PRIVATE
    ${OE_INCLUDE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
  )
  add_san(cchost.virtual)
  enable_coverage(cchost.virtual)
  target_link_libraries(cchost.virtual PRIVATE
    uv
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
endif()

# Client executable
add_executable(client ${CCF_DIR}/src/clients/client.cpp)
use_client_mbedtls(client)
target_link_libraries(client PRIVATE
  ${CMAKE_THREAD_LIBS_INIT}
  secp256k1.host
  http_parser.host
)
add_dependencies(client flatbuffers)

# Perf scenario executable
add_executable(scenario_perf_client
  ${CCF_DIR}/samples/perf_client/scenario_perf_client.cpp
)
use_client_mbedtls(scenario_perf_client)
target_link_libraries(scenario_perf_client PRIVATE
  ${CMAKE_THREAD_LIBS_INIT}
  secp256k1.host
  http_parser.host
)
add_dependencies(scenario_perf_client flatbuffers)

# Lua for host and enclave
add_enclave_library_c(lua.enclave "${LUA_SOURCES}")
target_compile_definitions(lua.enclave PRIVATE NO_IO)
add_library(lua.host STATIC ${LUA_SOURCES})
target_compile_definitions(lua.host PRIVATE NO_IO)
set_property(TARGET lua.host PROPERTY POSITION_INDEPENDENT_CODE ON)

# HTTP parser
add_enclave_library_c(http_parser.enclave "${HTTP_PARSER_SOURCES}")
set_property(TARGET http_parser.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
add_enclave_library_c(http_parser.host "${HTTP_PARSER_SOURCES}")
set_property(TARGET http_parser.host PROPERTY POSITION_INDEPENDENT_CODE ON)

# Common test args for Python scripts starting up CCF networks
if(PBFT)
  set(CONSENSUS_ARG "pbft")
else()
  set(CONSENSUS_ARG "raft")
endif()

set(CCF_NETWORK_TEST_ARGS
  ${TEST_IGNORE_QUOTE}
  ${TEST_ENCLAVE_TYPE}
  -l ${TEST_HOST_LOGGING_LEVEL}
  -g ${CCF_DIR}/src/runtime_config/gov.lua
  --consensus ${CONSENSUS_ARG}
  --default-curve ${DEFAULT_PARTICIPANTS_CURVE}
)

# SNIPPET: Lua generic application
add_enclave_lib(luagenericenc ${CCF_DIR}/src/apps/luageneric/oe_sign.conf ${CCF_DIR}/src/apps/sample_key.pem SRCS ${CCF_DIR}/src/apps/luageneric/luageneric.cpp)

# Samples

## Helper for building clients inheriting from perf_client
function(add_client_exe name)

  cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS
    ""
    ""
    "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  add_executable(${name}
    ${PARSED_ARGS_SRCS}
  )

  target_link_libraries(${name} PRIVATE
    ${CMAKE_THREAD_LIBS_INIT}
  )

  add_dependencies(${name} flatbuffers)
  target_include_directories(${name} PRIVATE
    ${CCF_DIR}/samples/perf_client
    ${PARSED_ARGS_INCLUDE_DIRS}
  )

  use_client_mbedtls(${name})

endfunction()

## Helper for building end-to-end function tests using the python infrastructure
function(add_e2e_test)
  cmake_parse_arguments(PARSE_ARGV 0 PARSED_ARGS
    ""
    "NAME;PYTHON_SCRIPT;IS_SUITE;CURL_CLIENT"
    "ADDITIONAL_ARGS"
  )

  if (BUILD_END_TO_END_TESTS)
    add_test(
      NAME ${PARSED_ARGS_NAME}
      COMMAND ${PYTHON} ${PARSED_ARGS_PYTHON_SCRIPT}
        -b .
        --label ${PARSED_ARGS_NAME}
        ${CCF_NETWORK_TEST_ARGS}
        ${PARSED_ARGS_ADDITIONAL_ARGS}
    )

    ## Make python test client framework importable
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY
        ENVIRONMENT "PYTHONPATH=${CCF_DIR}/tests:${CMAKE_CURRENT_BINARY_DIR}:$ENV{PYTHONPATH}"
    )
    if (${PARSED_ARGS_IS_SUITE})
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY
          LABELS suite
      )
    else()
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY
          LABELS end_to_end
      )
    endif()
    if (HTTP)
      set_property(
        TEST ${PARSED_ARGS_NAME}
        APPEND
        PROPERTY
          ENVIRONMENT "HTTP=ON"
      )
      if (${PARSED_ARGS_CURL_CLIENT})
        set_property(
          TEST ${PARSED_ARGS_NAME}
          APPEND
          PROPERTY
            ENVIRONMENT "CURL_CLIENT=ON"
        )
      endif()
    endif()
  endif()
endfunction()

## Helper for building end-to-end perf tests using the python infrastucture
function(add_perf_test)

  cmake_parse_arguments(PARSE_ARGV 0 PARSED_ARGS
    ""
    "NAME;PYTHON_SCRIPT;CLIENT_BIN;VERIFICATION_FILE;LABEL"
    "ADDITIONAL_ARGS"
  )

  if(PARSED_ARGS_VERIFICATION_FILE)
    set(VERIFICATION_ARG "--verify ${PARSED_ARGS_VERIFICATION_FILE}")
  else()
    unset(VERIFICATION_ARG)
  endif()

  if(PARSED_ARGS_LABEL)
    set(LABEL_ARG "${PARSED_ARGS_LABEL}_${TESTS_SUFFIX}")
  else()
    set(LABEL_ARG "${PARSED_ARGS_NAME}_${TESTS_SUFFIX}")
  endif()

  add_test(
    NAME ${PARSED_ARGS_NAME}
    COMMAND ${PYTHON} ${PARSED_ARGS_PYTHON_SCRIPT}
      -b .
      -c ${PARSED_ARGS_CLIENT_BIN}
      ${CCF_NETWORK_TEST_ARGS}
      --write-tx-times
      ${VERIFICATION_ARG}
      --label ${LABEL_ARG}
      ${PARSED_ARGS_ADDITIONAL_ARGS}
  )

  ## Make python test client framework importable
  set_property(
    TEST ${PARSED_ARGS_NAME}
    APPEND
    PROPERTY
      ENVIRONMENT "PYTHONPATH=${CCF_DIR}/tests:${CMAKE_CURRENT_BINARY_DIR}:$ENV{PYTHONPATH}"
  )
  set_property(
    TEST ${PARSED_ARGS_NAME}
    APPEND
    PROPERTY
      LABELS perf
  )
  if (HTTP)
    set_property(
      TEST ${PARSED_ARGS_NAME}
      APPEND
      PROPERTY
        ENVIRONMENT "HTTP=ON"
    )
  endif()
endfunction()

  ## Picobench wrapper
  function(add_picobench name)
    cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS
      ""
      ""
      "SRCS;INCLUDE_DIRS;LINK_LIBS"
    )

    add_executable(${name}
      ${PARSED_ARGS_SRCS}
    )

    target_include_directories(${name} PRIVATE
      src
      ${PARSED_ARGS_INCLUDE_DIRS}
    )

    add_dependencies(${name} flatbuffers)

    target_link_libraries(${name} PRIVATE
      ${CMAKE_THREAD_LIBS_INIT}
      ${PARSED_ARGS_LINK_LIBS}
    )

    # -Wall -Werror catches a number of warnings in picobench
    target_include_directories(${name} SYSTEM PRIVATE 3rdparty)

    add_test(
      NAME ${name}
      COMMAND bash -c "$<TARGET_FILE:${name}> --samples=1000 --out-fmt=csv --output=${name}.csv && cat ${name}.csv"
    )

    use_client_mbedtls(${name})

    set_property(TEST ${name} PROPERTY LABELS benchmark)
  endfunction()