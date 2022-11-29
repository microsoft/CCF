# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(protobuf_BUILD_SHARED_LIBS_DEFAULT OFF)
set(protobuf_BUILD_TESTS OFF)
set(protobuf_WITH_ZLIB OFF)
set(protobuf_BUILD_PROTOC_BINARIES OFF)
set(protobuf_INSTALL OFF)

set(CMAKE_POLICY_DEFAULT_CMP0077 NEW) # Removes warnings when setting

# "protobuf_..." variable above
add_subdirectory(${CCF_3RD_PARTY_EXPORTED_DIR}/protobuf EXCLUDE_FROM_ALL)

add_custom_target(dummy ALL DEPENDS libprotobuf)

get_target_property(LIBPROTOBUF_SOURCES libprotobuf SOURCES)

set(PROTOBUF_TARGETS "protobuf.virtual")
add_host_library(protobuf.virtual ${LIBPROTOBUF_SOURCES})

if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library(protobuf.enclave ${LIBPROTOBUF_SOURCES})
  list(APPEND PROTOBUF_TARGETS "protobuf.enclave")
  install(
    TARGETS protobuf.enclave
    EXPORT ccf
    DESTINATION lib
  )
elseif(COMPILE_TARGET STREQUAL "snp")
  add_host_library(protobuf.snp ${LIBPROTOBUF_SOURCES})
  list(APPEND PROTOBUF_TARGETS "protobuf.snp")
  install(
    TARGETS protobuf.snp
    EXPORT ccf
    DESTINATION lib
  )
else()
  install(
    TARGETS protobuf.virtual
    EXPORT ccf
    DESTINATION lib
  )
endif()

foreach(TARGET ${PROTOBUF_TARGETS})
  target_include_directories(
    ${TARGET}
    PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_EXPORTED_DIR}/protobuf/src>
           $<INSTALL_INTERFACE:include/3rdparty/protobuf>
  )

  target_compile_options(
    ${TARGET}
    PUBLIC
      "-Wno-deprecated-enum-enum-conversion" # Remove warnings in
      # generated_message_tctable_impl.h
      "-Wno-invalid-noreturn" # https://github.com/protocolbuffers/protobuf/issues/9817
  )
endforeach()
