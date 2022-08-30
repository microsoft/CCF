# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# TODO: Fix those
set(PROTOC_BINARY_DIR "/opt/protoc/bin")
set(PROTOBUF_BUILD_DIR ${CMAKE_BINARY_DIR}/3rdparty/internal/protobuf)

# TODO: This is hacky. We should copy the .h and .inc files properly,
# or maybe cmake install the protobuf library directly?
set(PROTOBUF_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/3rdparty/internal/protobuf/src/)

file(GLOB PROTO_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.proto)

foreach(proto_file ${PROTO_FILES})
    message(STATUS ${proto_file}) # TODO: Remove
    get_filename_component(PROTO_NAME ${proto_file} NAME)
    get_filename_component(PROTO_NAME_WE ${proto_file} NAME_WE)

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.h
        ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.cc
        COMMAND ${PROTOC_BINARY_DIR}/protoc --proto_path=${CMAKE_CURRENT_SOURCE_DIR}
        --cpp_out=${CMAKE_CURRENT_BINARY_DIR} ${proto_file}
        COMMENT "Generate C++ source files from protobuf file ${PROTO_NAME}")

    # enclave
    add_enclave_library(${PROTO_NAME_WE}.enclave ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.h)
    target_include_directories(${PROTO_NAME_WE}.enclave PUBLIC ${PROTOBUF_INCLUDE_DIR})

    # virtual
    add_host_library(${PROTO_NAME_WE}.virtual ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME_WE}.pb.h)
    target_include_directories(${PROTO_NAME_WE}.virtual PUBLIC ${PROTOBUF_INCLUDE_DIR})
endforeach()