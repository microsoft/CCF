# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# protoc should be installed under /opt/protoc
set(PROTOC_BINARY_PATH "/opt/protoc/bin/protoc")

if(EXISTS ${PROTOC_BINARY_PATH})
  message(STATUS "Found protobuf compiler: ${PROTOC_BINARY_PATH}")
else()
  message(FATAL_ERROR "Cannot find protobuf compiler: ${PROTOC_BINARY_PATH}")
endif()

set(PROTOBUF_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/3rdparty/internal/protobuf/src/)

file(GLOB PROTO_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.proto)

foreach(proto_file ${PROTO_FILES})
  get_filename_component(PROTO_NAME ${proto_file} NAME)
  get_filename_component(PROTO_NAME_WE ${proto_file} NAME_WE)
  message(TRACE "Generating source files from proto file ${PROTO_NAME}")

  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.h
           ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.cc
    COMMAND ${PROTOC_BINARY_PATH} --proto_path=${CMAKE_CURRENT_SOURCE_DIR}
            --cpp_out=${CMAKE_CURRENT_BINARY_DIR} ${proto_file}
    COMMENT "Generate C++ source files from protobuf file ${PROTO_NAME}"
    DEPENDS ${proto_file}
  )

  add_enclave_library(
    ${PROTO_NAME_WE}.enclave ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.h
  )
  target_include_directories(
    ${PROTO_NAME_WE}.enclave PUBLIC ${PROTOBUF_INCLUDE_DIR}
  )

  add_host_library(
    ${PROTO_NAME_WE}.virtual ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.h
  )
  target_include_directories(
    ${PROTO_NAME_WE}.virtual PUBLIC ${PROTOBUF_INCLUDE_DIR}
  )
endforeach()
