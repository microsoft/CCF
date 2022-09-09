# Build t_cose
set(T_COSE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/t_cose")
set(T_COSE_SRC "${T_COSE_DIR}/src")
set(T_COSE_INC "${T_COSE_DIR}/inc")
set(T_COSE_DEFS -DT_COSE_USE_OPENSSL_CRYPTO=1)
# https://github.com/laurencelundblade/t_cose/issues/50
set(T_COSE_OPTS_INTERFACE -Wno-c99-extensions)
set(T_COSE_SRCS
  "${T_COSE_SRC}/t_cose_parameters.c"
  "${T_COSE_SRC}/t_cose_sign1_verify.c"
  "${T_COSE_SRC}/t_cose_util.c"
  "${T_COSE_DIR}/crypto_adapters/t_cose_openssl_crypto.c"
)
if ("sgx" IN_LIST COMPILE_TARGETS)
  add_enclave_library_c(t_cose.enclave ${T_COSE_SRCS})
  target_compile_definitions(t_cose.enclave PRIVATE ${T_COSE_DEFS})
  target_compile_options(t_cose.enclave INTERFACE ${T_COSE_OPTS_INTERFACE})
  target_include_directories(t_cose.enclave PUBLIC "${T_COSE_INC}" PRIVATE "${T_COSE_SRC}")
  target_link_libraries(t_cose.enclave PUBLIC qcbor.enclave)
  # TODO why is this needed?
  target_link_libraries(t_cose.enclave PRIVATE openenclave::oecryptoopenssl)
endif()
if ("virtual" IN_LIST COMPILE_TARGETS)
  find_package(OpenSSL REQUIRED)
  add_library(t_cose.virtual STATIC ${T_COSE_SRCS})
  target_compile_definitions(t_cose.virtual PRIVATE ${T_COSE_DEFS})
  target_compile_options(t_cose.virtual INTERFACE ${T_COSE_OPTS_INTERFACE})
  target_include_directories(t_cose.virtual PUBLIC "${T_COSE_INC}" PRIVATE "${T_COSE_SRC}")
  target_link_libraries(t_cose.virtual PUBLIC qcbor.virtual OpenSSL::Crypto)
  set_property(TARGET t_cose.virtual PROPERTY POSITION_INDEPENDENT_CODE ON)
  scitt_add_san(t_cose.virtual)
endif()