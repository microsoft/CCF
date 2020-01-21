# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(ALLOWED_TARGETS "sgx;virtual")
set(IS_VALID_TARGET "FALSE")
foreach(REQUESTED_TARGET ${TARGET})
  if(${REQUESTED_TARGET} IN_LIST ALLOWED_TARGETS)
    set(IS_VALID_TARGET "TRUE")
  else()
    message(FATAL_ERROR "${REQUESTED_TARGET} is not a valid target. Choose from: ${ALLOWED_TARGETS}")
  endif()
endforeach()

if((NOT ${IS_VALID_TARGET}))
  message(FATAL_ERROR "Variable list 'TARGET' must include at least one supported target. Choose from: ${ALLOWED_TARGETS}")
endif()

# Sign a built enclave library with oesign
function(sign_app_library name app_oe_conf_path enclave_sign_key_path)
  if(TARGET ${name})
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.signed
      COMMAND openenclave::oesign sign
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
  endif()
endfunction()

# Util functions used by add_enclave_lib and others
function(enable_quote_code name)
  if (QUOTES_ENABLED)
    target_compile_definitions(${name} PRIVATE -DGET_QUOTE)
  endif()
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

separate_arguments(COVERAGE_FLAGS UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping")
separate_arguments(COVERAGE_LINK UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping")

function(enable_coverage name)
  if (COVERAGE)
    target_compile_options(${name} PRIVATE ${COVERAGE_FLAGS})
    target_link_libraries(${name} PRIVATE ${COVERAGE_LINK})
  endif()
endfunction()

function(use_client_mbedtls name)
  target_include_directories(${name} PRIVATE ${CLIENT_MBEDTLS_INCLUDE_DIR})
  target_link_libraries(${name} PRIVATE ${CLIENT_MBEDTLS_LIBRARIES})
endfunction()

function(use_oe_mbedtls name)
  target_link_libraries(${name} PRIVATE
    openenclave::oeenclave
    openenclave::oelibcxx
  )
endfunction()

if(NOT CCF_GENERATED_DIR)
  set(CCF_GENERATED_DIR ${CCF_DIR}/generated)
endif()

add_custom_target(flatbuffers ALL
  DEPENDS ${CCF_GENERATED_DIR}/frame_generated.h
)

# Enclave library wrapper
function(add_enclave_lib name)

  cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS
    ""
    ""
    "SRCS;INCLUDE_DIRS;LINK_LIBS"
  )

  if("sgx" IN_LIST TARGET)
    add_library(${name} SHARED
      ${ENCLAVE_FILES}
      ${PARSED_ARGS_SRCS}
      ${CCF_GENERATED_DIR}/ccf_t.cpp
    )

    target_compile_definitions(${name} PRIVATE
      INSIDE_ENCLAVE
      _LIBCPP_HAS_THREAD_API_PTHREAD
    )
    target_compile_options(${name} PRIVATE
      -nostdinc
      -nostdinc++
      -U__linux__
    )
    target_include_directories(${name} SYSTEM PRIVATE
      ${PARSED_ARGS_INCLUDE_DIRS}
      ${EVERCRYPT_INC}
      ${CMAKE_CURRENT_BINARY_DIR}
      ${QUICKJS_INC}
    )
    add_dependencies(${name} flatbuffers)

    if (PBFT)
      target_link_libraries(${name} PRIVATE
        libbyz.enclave
      )
    endif()
    target_link_libraries(${name} PRIVATE
      -nostdlib -nodefaultlibs -nostartfiles
      -Wl,--no-undefined
      -Wl,-Bstatic,-Bsymbolic,--export-dynamic,-pie
      quickjs.enclave
      -lgcc
      ${PARSED_ARGS_LINK_LIBS}
      openenclave::oeenclave
      openenclave::oelibcxx
      ${ENCLAVE_LIBS}
      http_parser.enclave
    )
    set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)

    enable_quote_code(${name})
  endif()

  if("virtual" IN_LIST TARGET)
    ## Build a virtual enclave, loaded as a shared library without OE
    set(virt_name ${name}.virtual)
    add_library(${virt_name} SHARED
      ${ENCLAVE_FILES}
      ${PARSED_ARGS_SRCS}
      ${CCF_GENERATED_DIR}/ccf_t.cpp
    )
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
      ${CMAKE_CURRENT_BINARY_DIR}
      ${QUICKJS_INC}
      ${OE_INCLUDEDIR} # Virtual libraries don't link against OE, but do share includes
    )
    add_dependencies(${virt_name} flatbuffers)

    if (PBFT)
      target_link_libraries(${virt_name} PRIVATE
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
      quickjs.host
    )
    set_property(TARGET ${virt_name} PROPERTY POSITION_INDEPENDENT_CODE ON)

    enable_coverage(${virt_name})
    use_client_mbedtls(${virt_name})
    add_san(${virt_name})
  endif()
endfunction()