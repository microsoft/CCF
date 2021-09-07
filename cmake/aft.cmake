# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# AFT

set(AFT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/impl/execution.cpp)

if("sgx" IN_LIST COMPILE_TARGETS)
  add_enclave_library(aft.enclave ${AFT_SRC})
  use_oe_mbedtls(aft.enclave)
  install(
    TARGETS aft.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

if("virtual" IN_LIST COMPILE_TARGETS)

  add_library(aft.virtual STATIC ${AFT_SRC})
  add_san(aft.virtual)
  target_compile_options(aft.virtual PRIVATE ${COMPILE_LIBCXX})
  target_compile_definitions(
    aft.virtual PUBLIC INSIDE_ENCLAVE VIRTUAL_ENCLAVE
                       _LIBCPP_HAS_THREAD_API_PTHREAD
  )
  set_property(TARGET aft.virtual PROPERTY POSITION_INDEPENDENT_CODE ON)
  use_client_mbedtls(aft.virtual)
  install(
    TARGETS aft.virtual
    EXPORT ccf
    DESTINATION lib
  )
endif()
