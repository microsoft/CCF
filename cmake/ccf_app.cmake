# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(ALLOWED_TARGETS "sgx;virtual")

set(COMPILE_TARGETS
    "sgx;virtual"
    CACHE
      STRING
      "List of target compilation platforms. Choose from: ${ALLOWED_TARGETS}"
)

set(IS_VALID_TARGET "FALSE")
foreach(REQUESTED_TARGET ${COMPILE_TARGETS})
  if(${REQUESTED_TARGET} IN_LIST ALLOWED_TARGETS)
    set(IS_VALID_TARGET "TRUE")
  else()
    message(
      FATAL_ERROR
        "${REQUESTED_TARGET} is not a valid target. Choose from: ${ALLOWED_TARGETS}"
    )
  endif()
endforeach()

if((NOT ${IS_VALID_TARGET}))
  message(
    FATAL_ERROR
      "Variable list 'COMPILE_TARGETS' must include at least one supported target. Choose from: ${ALLOWED_TARGETS}"
  )
endif()

find_package(OpenEnclave 0.8 CONFIG REQUIRED)
# As well as pulling in openenclave:: targets, this sets variables which can be
# used for our edge cases (eg - for virtual libraries). These do not follow the
# standard naming patterns, for example use OE_INCLUDEDIR rather than
# OpenEnclave_INCLUDE_DIRS

# Sign a built enclave library with oesign
function(sign_app_library name app_oe_conf_path enclave_sign_key_path)
  if(TARGET ${name})
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.signed
      COMMAND
        openenclave::oesign sign -e ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so -c
        ${app_oe_conf_path} -k ${enclave_sign_key_path}
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so ${app_oe_conf_path}
              ${enclave_sign_key_path}
    )

    add_custom_target(
      ${name}_signed ALL
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.signed
    )
  endif()
endfunction()

# Util functions used by add_ccf_app and others
function(enable_quote_code name)
  if(QUOTES_ENABLED)
    target_compile_definitions(${name} PUBLIC -DGET_QUOTE)
  endif()
endfunction()

function(add_san name)
  if(SAN)
    target_compile_options(
      ${name}
      PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
              -fno-sanitize-recover=all -fno-sanitize=function
              -fsanitize-blacklist=${CCF_DIR}/src/ubsan.blacklist
    )
    target_link_libraries(
      ${name}
      PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
              -fno-sanitize-recover=all -fno-sanitize=function
              -fsanitize-blacklist=${CCF_DIR}/src/ubsan.blacklist
    )
  endif()
endfunction()

separate_arguments(
  COVERAGE_FLAGS UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping"
)
separate_arguments(
  COVERAGE_LINK UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping"
)

function(enable_coverage name)
  if(COVERAGE)
    target_compile_options(${name} PRIVATE ${COVERAGE_FLAGS})
    target_link_libraries(${name} PRIVATE ${COVERAGE_LINK})
  endif()
endfunction()

function(use_client_mbedtls name)
  target_include_directories(${name} PRIVATE ${CLIENT_MBEDTLS_INCLUDE_DIR})
  target_link_libraries(${name} PRIVATE ${CLIENT_MBEDTLS_LIBRARIES})
endfunction()

function(use_oe_mbedtls name)
  target_link_libraries(
    ${name} PRIVATE openenclave::oeenclave openenclave::oelibcxx
                    openenclave::oelibc
  )
endfunction()

# Enclave library wrapper
function(add_ccf_app name)

  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" ""
    "SRCS;INCLUDE_DIRS;LINK_LIBS_ENCLAVE;LINK_LIBS_VIRTUAL"
  )

  add_custom_target(${name} ALL)

  if("sgx" IN_LIST COMPILE_TARGETS)
    set(enc_name ${name}.enclave)

    add_library(${enc_name} SHARED ${PARSED_ARGS_SRCS})

    target_include_directories(
      ${enc_name} SYSTEM PRIVATE ${PARSED_ARGS_INCLUDE_DIRS}
    )

    target_link_libraries(
      ${enc_name}
      PRIVATE ${PARSED_ARGS_LINK_LIBS_ENCLAVE}
              # These oe libraries must be linked in correct order, so they are
              # re-declared here
              openenclave::oeenclave
              openenclave::oecore
              openenclave::oesyscall
              ccf.enclave
    )

    set_property(TARGET ${enc_name} PROPERTY POSITION_INDEPENDENT_CODE ON)

    add_dependencies(${name} ${enc_name})
  endif()

  if("virtual" IN_LIST COMPILE_TARGETS)
    # Build a virtual enclave, loaded as a shared library without OE
    set(virt_name ${name}.virtual)

    add_library(${virt_name} SHARED ${PARSED_ARGS_SRCS})

    target_include_directories(
      ${virt_name} SYSTEM PRIVATE ${PARSED_ARGS_INCLUDE_DIRS}
    )

    target_link_libraries(
      ${virt_name} PRIVATE ${PARSED_ARGS_LINK_LIBS_VIRTUAL} ccf.virtual
    )

    set_property(TARGET ${virt_name} PROPERTY POSITION_INDEPENDENT_CODE ON)

    enable_coverage(${virt_name})
    use_client_mbedtls(${virt_name})
    add_san(${virt_name})

    add_dependencies(${name} ${virt_name})
  endif()
endfunction()
