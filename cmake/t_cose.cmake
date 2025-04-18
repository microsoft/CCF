# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Build t_cose
set(T_COSE_DIR "${CCF_3RD_PARTY_EXPORTED_DIR}/t_cose")
set(T_COSE_SRC "${T_COSE_DIR}/src")
set(T_COSE_DEFS -DT_COSE_USE_OPENSSL_CRYPTO=1
                -DT_COSE_DISABLE_SHORT_CIRCUIT_SIGN=1
)
set(T_COSE_SRCS
    "${T_COSE_SRC}/t_cose_parameters.c" "${T_COSE_SRC}/t_cose_sign1_verify.c"
    "${T_COSE_SRC}/t_cose_sign1_sign.c" "${T_COSE_SRC}/t_cose_util.c"
    "${T_COSE_DIR}/crypto_adapters/t_cose_openssl_crypto.c"
)
if(COMPILE_TARGET STREQUAL "snp")
  find_package(OpenSSL REQUIRED)
  add_library(t_cose.snp STATIC ${T_COSE_SRCS})
  target_compile_definitions(t_cose.snp PRIVATE ${T_COSE_DEFS})
  target_compile_options(t_cose.snp INTERFACE ${T_COSE_OPTS_INTERFACE})

  target_include_directories(t_cose.snp PRIVATE "${T_COSE_SRC}")

  target_include_directories(
    t_cose.snp
    PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_EXPORTED_DIR}/t_cose/inc>
           $<INSTALL_INTERFACE:include/3rdparty/t_cose/inc>
  )

  target_link_libraries(t_cose.snp PUBLIC qcbor.snp crypto)
  set_property(TARGET t_cose.snp PROPERTY POSITION_INDEPENDENT_CODE ON)
  add_san(t_cose.snp)

  if(CCF_DEVEL)
    install(
      TARGETS t_cose.snp
      EXPORT ccf
      DESTINATION lib
    )
  endif()
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
