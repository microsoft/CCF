# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

option(ENABLE_V8 "Enable building of the js_v8 app" OFF)
if(ENABLE_V8)
  message(STATUS "WARNING: V8 utilisation is experimental")

  option(V8_DEBUG "Use V8 debug build" OFF)
  if(V8_DEBUG)
    set(V8_BUILD_TYPE "debug")
  else()
    set(V8_BUILD_TYPE "release")
  endif()
  message(STATUS "Using V8 ${V8_BUILD_TYPE} build")

  set(v8_include_dir_relative include)
  set(v8_lib_relative lib/libv8_monolith.a)
  set(v8_base_dir ${CMAKE_CURRENT_SOURCE_DIR}/build-v8)
  set(v8_virtual_dir ${v8_base_dir}/${V8_BUILD_TYPE}-virtual)
  set(v8_virtual_include_dir ${v8_virtual_dir}/${v8_include_dir_relative})
  set(v8_virtual_lib ${v8_virtual_dir}/${v8_lib_relative})
  set(v8_sgx_dir ${v8_base_dir}/${V8_BUILD_TYPE}-sgx)
  set(v8_sgx_include_dir ${v8_sgx_dir}/${v8_include_dir_relative})
  set(v8_sgx_lib ${v8_sgx_dir}/${v8_lib_relative})

  set(v8_defs V8_CC_MSVC=0)

  set(js_v8_dir ${CCF_DIR}/src/apps/js_v8)
  set(js_v8_src
      ${js_v8_dir}/js_v8_base.cpp
      ${js_v8_dir}/v8_runner.cpp
      ${js_v8_dir}/v8_util.cpp
      ${js_v8_dir}/kv_module_loader.cpp
      ${js_v8_dir}/tmpl/console_global.cpp
      ${js_v8_dir}/tmpl/ccf_global.cpp
      ${js_v8_dir}/tmpl/request.cpp
      ${js_v8_dir}/tmpl/request_authn_identity.cpp
      ${js_v8_dir}/tmpl/request_body.cpp
      ${js_v8_dir}/tmpl/string_map.cpp
      ${js_v8_dir}/tmpl/kv_store.cpp
      ${js_v8_dir}/tmpl/kv_map.cpp
      ${js_v8_dir}/tmpl/historical_state.cpp
      ${js_v8_dir}/tmpl/receipt.cpp
      ${js_v8_dir}/tmpl/consensus.cpp
      ${js_v8_dir}/tmpl/historical.cpp
      ${js_v8_dir}/tmpl/rpc.cpp
      ${js_v8_dir}/tmpl/crypto.cpp
  )

  if("virtual" IN_LIST COMPILE_TARGETS)
    add_library(js_v8_base.virtual STATIC ${js_v8_src})
    add_san(js_v8_base.virtual)
    add_warning_checks(js_v8_base.virtual)
    target_include_directories(
      js_v8_base.virtual PRIVATE ${js_v8_dir} ${v8_virtual_include_dir}
    )
    target_link_libraries(
      js_v8_base.virtual PUBLIC ccf.virtual ${v8_virtual_lib}
    )
    target_compile_options(js_v8_base.virtual PRIVATE ${COMPILE_LIBCXX})
    target_compile_definitions(
      js_v8_base.virtual PUBLIC INSIDE_ENCLAVE VIRTUAL_ENCLAVE
                                _LIBCPP_HAS_THREAD_API_PTHREAD ${v8_defs}
    )
    set_property(
      TARGET js_v8_base.virtual PROPERTY POSITION_INDEPENDENT_CODE ON
    )
    install(
      TARGETS js_v8_base.virtual
      EXPORT ccf
      DESTINATION lib
    )
  endif()

  if("sgx" IN_LIST COMPILE_TARGETS)
    add_enclave_library(
      v8_oe_stubs.enclave ${CCF_DIR}/src/apps/js_v8/v8_oe_stubs.cpp
    )
    add_lvi_mitigations(v8_oe_stubs.enclave)

    add_enclave_library(js_v8_base.enclave ${js_v8_src})
    target_include_directories(
      js_v8_base.enclave PRIVATE ${js_v8_dir} ${v8_sgx_include_dir}
    )
    target_link_libraries(
      js_v8_base.enclave PUBLIC ccf.enclave ${v8_sgx_lib} v8_oe_stubs.enclave
    )
    target_compile_definitions(js_v8_base.enclave PUBLIC ${v8_defs})
    add_lvi_mitigations(js_v8_base.enclave)
    install(
      TARGETS js_v8_base.enclave v8_oe_stubs.enclave
      EXPORT ccf
      DESTINATION lib
    )
  endif()

  set(v8_supported_targets virtual)
  if(ENABLE_V8_SGX)
    list(APPEND v8_supported_targets sgx)
  endif()

  add_ccf_app(
    js_v8
    SRCS ${CCF_DIR}/src/apps/js_v8/js_v8.cpp
    LINK_LIBS_ENCLAVE js_v8_base.enclave js_openenclave.enclave
    LINK_LIBS_VIRTUAL js_v8_base.virtual js_openenclave.virtual INSTALL_LIBS ON
  )
  sign_app_library(
    js_v8.enclave ${CCF_DIR}/src/apps/js_v8/oe_sign.conf
    ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem INSTALL_LIBS ON
  )
endif()
