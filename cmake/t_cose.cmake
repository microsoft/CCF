# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Build t_cose
set(T_COSE_DIR "${CCF_3RD_PARTY_EXPORTED_DIR}/t_cose")
set(T_COSE_SRC "${T_COSE_DIR}/src")
set(T_COSE_DEFS -DT_COSE_USE_OPENSSL_CRYPTO=1 -DT_COSE_DISABLE_SHORT_CIRCUIT_SIGN=1)
set(T_COSE_SRCS
    "${T_COSE_SRC}/t_cose_parameters.c" "${T_COSE_SRC}/t_cose_sign1_verify.c"
    "${T_COSE_SRC}/t_cose_util.c"
    "${T_COSE_DIR}/crypto_adapters/t_cose_openssl_crypto.c"
)
if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library_c(t_cose.enclave ${T_COSE_SRCS})
  target_compile_definitions(t_cose.enclave PRIVATE ${T_COSE_DEFS})
  target_compile_options(t_cose.enclave INTERFACE ${T_COSE_OPTS_INTERFACE})

  target_include_directories(t_cose.enclave PRIVATE "${T_COSE_SRC}")
  target_include_directories(
    t_cose.enclave
    PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_EXPORTED_DIR}/t_cose/inc>
           $<INSTALL_INTERFACE:include/3rdparty/t_cose/inc>
  )

  target_link_libraries(t_cose.enclave PUBLIC qcbor.enclave)
  # This is needed to get the OpenSSL includes from Open Enclave
  target_link_libraries(t_cose.enclave PRIVATE openenclave::oecryptoopenssl)

  install(
    TARGETS t_cose.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

find_package(OpenSSL REQUIRED)
add_library(t_cose.host STATIC ${T_COSE_SRCS})
target_compile_definitions(t_cose.host PRIVATE ${T_COSE_DEFS})
target_compile_options(t_cose.host INTERFACE ${T_COSE_OPTS_INTERFACE})

target_include_directories(t_cose.host PRIVATE "${T_COSE_SRC}")

target_include_directories(
  t_cose.host PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_EXPORTED_DIR}/t_cose/inc>
                     $<INSTALL_INTERFACE:include/3rdparty/t_cose/inc>
)

target_link_libraries(t_cose.host PUBLIC qcbor.host crypto)
set_property(TARGET t_cose.host PROPERTY POSITION_INDEPENDENT_CODE ON)
add_san(t_cose.host)

if(INSTALL_VIRTUAL_LIBRARIES)
  install(
    TARGETS t_cose.host
    EXPORT ccf
    DESTINATION lib
  )
endif()
