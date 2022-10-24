# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if("sgx" IN_LIST COMPILE_TARGETS)
  add_library(ravl.enclave INTERFACE)
  target_compile_definitions(ravl.enclave INTERFACE RAVL_HAVE_OPENSSL)
  target_include_directories(
    ravl.enclave
    INTERFACE
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/exported/ravl/include>
  )
  if(LVI_MITIGATIONS)
    target_link_libraries(
      ravl.enclave INTERFACE openenclave::oecryptoopenssl-lvi-cfg
    )
  else()
    target_link_libraries(ravl.enclave INTERFACE openenclave::oecryptoopenssl)
  endif()
  install(TARGETS ravl.enclave EXPORT ccf)
endif()

add_library(ravl.host INTERFACE)
target_compile_definitions(ravl.host INTERFACE RAVL_HAVE_OPENSSL)
target_include_directories(
  ravl.host
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/exported/ravl/include>
)
target_link_libraries(ravl.host INTERFACE crypto)
install(TARGETS ravl.host EXPORT ccf)
