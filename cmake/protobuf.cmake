# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(protobuf_BUILD_SHARED_LIBS_DEFAULT OFF)
set(protobuf_BUILD_TESTS OFF)
set(protobuf_WITH_ZLIB OFF)
set(protobuf_BUILD_PROTOC_BINARIES OFF)
set(protobuf_INSTALL OFF)

set(CMAKE_POLICY_DEFAULT_CMP0077 NEW) # Removes warnings when setting

# "protobuf_..." variable above
add_subdirectory(${CCF_3RD_PARTY_INTERNAL_DIR}/protobuf EXCLUDE_FROM_ALL)

add_custom_target(dummy ALL DEPENDS libprotobuf)

get_target_property(LIBPROTOBUF_SOURCES libprotobuf SOURCES)
get_target_property(LIBPROTOBUF_INCLUDE_DIRS libprotobuf INCLUDE_DIRECTORIES)

set(PROTOBUF_TARGETS "protobuf.virtual")
add_host_library(protobuf.virtual ${LIBPROTOBUF_SOURCES})

if("sgx" IN_LIST COMPILE_TARGETS)
  add_enclave_library(protobuf.enclave ${LIBPROTOBUF_SOURCES})
  list(APPEND PROTOBUF_TARGETS "protobuf.enclave")
endif()

foreach(TARGET ${PROTOBUF_TARGETS})
  target_include_directories(${TARGET} PUBLIC ${LIBPROTOBUF_INCLUDE_DIRS})
  target_compile_options(
    ${TARGET}
    PUBLIC
      "-Wno-deprecated-enum-enum-conversion" # Remove warnings in
      # generated_message_tctable_impl.h
      "-Wno-invalid-noreturn" # https://github.com/protocolbuffers/protobuf/issues/9817
  )
endforeach()
