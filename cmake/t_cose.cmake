# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Build t_cose
set(T_COSE_DIR "${CCF_3RD_PARTY_INTERNAL_DIR}/t_cose")
set(T_COSE_SRC "${T_COSE_DIR}/src")
set(T_COSE_DEFS -DT_COSE_USE_OPENSSL_CRYPTO=1
                -DT_COSE_DISABLE_SHORT_CIRCUIT_SIGN=1
)
set(T_COSE_SRCS
    "${T_COSE_SRC}/t_cose_parameters.c" "${T_COSE_SRC}/t_cose_sign1_verify.c"
    "${T_COSE_SRC}/t_cose_sign1_sign.c" "${T_COSE_SRC}/t_cose_util.c"
    "${T_COSE_DIR}/crypto_adapters/t_cose_openssl_crypto.c"
)

find_package(OpenSSL REQUIRED)
add_library(t_cose STATIC ${T_COSE_SRCS})
target_compile_definitions(t_cose PRIVATE ${T_COSE_DEFS})
target_compile_options(t_cose INTERFACE ${T_COSE_OPTS_INTERFACE})

target_include_directories(t_cose PRIVATE "${T_COSE_SRC}")
target_include_directories(
  t_cose PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_INTERNAL_DIR}/t_cose/inc>
)

target_link_libraries(t_cose PUBLIC qcbor)
set_property(TARGET t_cose PROPERTY POSITION_INDEPENDENT_CODE ON)
add_san(t_cose)

install(
  TARGETS t_cose
  EXPORT ccf
  DESTINATION lib
)
