# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# AFT

set(AFT_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/aft.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/impl/global_commit_handler.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/impl/startup_state_machine.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/impl/catchup_state_machine.cpp
)


if("sgx" IN_LIST COMPILE_TARGETS)
  add_library(aft.enclave STATIC ${AFT_SRC})
  target_compile_options(aft.enclave PRIVATE -nostdinc)
  target_compile_definitions(
    aft.enclave PRIVATE INSIDE_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD
                        __USE_SYSTEM_ENDIAN_H__
  )
  set_property(TARGET aft.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(
    aft.enclave PRIVATE ${CCF_DIR}/src/ds ${OE_TARGET_LIBC}
                        ${PARSED_ARGS_INCLUDE_DIRS} ${EVERCRYPT_INC}
  )
  use_oe_mbedtls(aft.enclave)
  install(
    TARGETS aft.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if("virtual" IN_LIST COMPILE_TARGETS)

  add_library(aft.host STATIC ${AFT_SRC})
  target_compile_options(aft.host PRIVATE -stdlib=libc++)
  set_property(TARGET aft.host PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(aft.host PRIVATE SYSTEM ${EVERCRYPT_INC})
  use_client_mbedtls(aft.host)
  install(
    TARGETS aft.host
    EXPORT ccf
    DESTINATION lib
  )

  # Unit tests
  add_unit_test(
    aft_unit_tests
    ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/aft/test/init.cpp
  )
  use_libbyz(aft_unit_tests)
  add_san(aft_unit_tests)
  set_property(TEST aft_unit_tests PROPERTY LABELS aft)
endif()