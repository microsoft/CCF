# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# protoc should be installed under /opt/protoc
set(PROTOC_BINARY_PATH "/opt/protoc/bin/protoc")

if(EXISTS ${PROTOC_BINARY_PATH})
  message(STATUS "Found protobuf compiler: ${PROTOC_BINARY_PATH}")
else()
  message(FATAL_ERROR "Cannot find protobuf compiler: ${PROTOC_BINARY_PATH}")
endif()

set(PROTOBUF_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/3rdparty/exported/protobuf/src/)

file(GLOB PROTO_FILES CONFIFURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.proto)

set_property(GLOBAL PROPERTY JOB_POOLS one_job=1)

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
  add_custom_target(
    ${PROTO_NAME_WE}_proto_cpp ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.h
            ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.cc
  )

  add_custom_command(
    OUTPUT
      ${CMAKE_SOURCE_DIR}/tests/external_executor/${PROTO_NAME_WE}_pb2.py
      ${CMAKE_SOURCE_DIR}/tests/external_executor/${PROTO_NAME_WE}_pb2_grpc.py
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build.sh ${proto_file}
            ${CMAKE_SOURCE_DIR}/tests/external_executor/
    COMMENT "Generate Python source file from protobuf file ${PROTO_NAME}"
    DEPENDS ${proto_file}
    JOB_POOL one_job
  )
  add_custom_target(
    ${PROTO_NAME_WE}_proto_python ALL
    DEPENDS
      ${CMAKE_SOURCE_DIR}/tests/external_executor/${PROTO_NAME_WE}_pb2.py
      ${CMAKE_SOURCE_DIR}/tests/external_executor/${PROTO_NAME_WE}_pb2_grpc.py
    JOB_POOL one_job
  )

  if(COMPILE_TARGET STREQUAL "sgx")
    add_enclave_library(
      ${PROTO_NAME_WE}.proto.enclave
      ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.cc
      ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.h
    )
    target_include_directories(
      ${PROTO_NAME_WE}.proto.enclave PUBLIC ${PROTOBUF_INCLUDE_DIR}
    )
  else()
    add_host_library(
      ${PROTO_NAME_WE}.proto.virtual
      ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.cc
      ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.h
    )
    target_include_directories(
      ${PROTO_NAME_WE}.proto.virtual PUBLIC ${PROTOBUF_INCLUDE_DIR}
    )
  endif()
endforeach()

# Add dependencies between proto libraries
if(COMPILE_TARGET STREQUAL "sgx")
  target_link_libraries(kv.proto.enclave PUBLIC http.proto.enclave)
else()
  target_link_libraries(kv.proto.virtual PUBLIC http.proto.virtual)
endif()
