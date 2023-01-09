# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# protoc should be installed under /opt/protoc
set(PROTOC_BINARY_PATH "/opt/protoc/bin/protoc")

if(EXISTS ${PROTOC_BINARY_PATH})
    message(STATUS "Found protobuf compiler: ${PROTOC_BINARY_PATH}")
else()
    message(FATAL_ERROR "Cannot find protobuf compiler: ${PROTOC_BINARY_PATH}")
endif()

add_custom_command(
    OUTPUT ${CCF_DIR}/src/endpoints/grpc/protobuf/status.pb.h
    ${CCF_DIR}/src/endpoints/grpc/protobuf/status.pb.cc
    COMMAND
    ${PROTOC_BINARY_PATH} --proto_path=${CCF_DIR}/src/endpoints/grpc/protobuf
    --cpp_out=${CCF_DIR}/src/endpoints/grpc/protobuf
    ${CCF_DIR}/src/endpoints/grpc/protobuf/status.proto
    COMMENT "Generate C++ source files for status.proto file"
    DEPENDS ${CCF_DIR}/src/endpoints/grpc/protobuf/status.proto
)

# TODO: Also add SNP and SGX versions
add_host_library(
    ccf_grpc.host ${CCF_DIR}/src/endpoints/grpc/protobuf/status.pb.cc
)
target_link_libraries(ccf_grpc.host PUBLIC protobuf.virtual)
target_include_directories(
    ccf_grpc.host
    PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/3rdparty/exported/protobuf/src/>
    $<INSTALL_INTERFACE:include/3rdparty/protobuf/src>
)

# Temporary hack until https://github.com/protocolbuffers/protobuf/pull/10107 is
# released
target_compile_definitions(
    ccf_grpc.host PUBLIC GOOGLE_PROTOBUF_INTERNAL_DONATE_STEAL_INLINE
)
add_san(ccf_grpc.host)
add_warning_checks(ccf_grpc.host)

if(INSTALL_VIRTUAL_LIBRARIES)
    install(
        TARGETS ccf_grpc.host
        EXPORT ccf
        DESTINATION lib
    )
endif()