# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Sign a built enclave library with oesign
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
      ${QUICKJS_INC}
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
      quickjs.enclave
      -lgcc
      ${PARSED_ARGS_LINK_LIBS}
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
      ${QUICKJS_INC}
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
      quickjs.host
    )
    enable_coverage(${virt_name})
    use_client_mbedtls(${virt_name})
    set_property(TARGET ${virt_name} PROPERTY POSITION_INDEPENDENT_CODE ON)
  endif()
endfunction()