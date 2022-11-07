# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(NGHTTP2_PREFIX
    ${CCF_3RD_PARTY_EXPORTED_DIR}/nghttp2
    CACHE PATH "Prefix to NGHTTP2 library"
)

set(NGHTTP2_SRCS
    ${NGHTTP2_PREFIX}/nghttp2_buf.c
    ${NGHTTP2_PREFIX}/nghttp2_callbacks.c
    ${NGHTTP2_PREFIX}/nghttp2_debug.c
    ${NGHTTP2_PREFIX}/nghttp2_frame.c
    ${NGHTTP2_PREFIX}/nghttp2_hd.c
    ${NGHTTP2_PREFIX}/nghttp2_hd_huffman.c
    ${NGHTTP2_PREFIX}/nghttp2_hd_huffman_data.c
    ${NGHTTP2_PREFIX}/nghttp2_helper.c
    ${NGHTTP2_PREFIX}/nghttp2_http.c
    ${NGHTTP2_PREFIX}/nghttp2_map.c
    ${NGHTTP2_PREFIX}/nghttp2_mem.c
    ${NGHTTP2_PREFIX}/nghttp2_npn.c
    ${NGHTTP2_PREFIX}/nghttp2_option.c
    ${NGHTTP2_PREFIX}/nghttp2_outbound_item.c
    ${NGHTTP2_PREFIX}/nghttp2_pq.c
    ${NGHTTP2_PREFIX}/nghttp2_priority_spec.c
    ${NGHTTP2_PREFIX}/nghttp2_queue.c
    ${NGHTTP2_PREFIX}/nghttp2_rcbuf.c
    ${NGHTTP2_PREFIX}/nghttp2_extpri.c
    ${NGHTTP2_PREFIX}/nghttp2_session.c
    ${NGHTTP2_PREFIX}/nghttp2_stream.c
    ${NGHTTP2_PREFIX}/nghttp2_submit.c
    ${NGHTTP2_PREFIX}/nghttp2_version.c
)

if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library_c(nghttp2.enclave ${NGHTTP2_SRCS})
  target_include_directories(
    nghttp2.enclave PUBLIC $<BUILD_INTERFACE:${NGHTTP2_PREFIX}/includes>
                           $<INSTALL_INTERFACE:include/3rdparty/nghttp2>
  )
  target_compile_definitions(
    nghttp2.enclave PUBLIC -DNGHTTP2_STATICLIB -DHAVE_ARPA_INET_H=1
  )

  install(
    TARGETS nghttp2.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

add_library(nghttp2.host STATIC ${NGHTTP2_SRCS})
target_include_directories(
  nghttp2.host PUBLIC $<BUILD_INTERFACE:${NGHTTP2_PREFIX}/includes>
                      $<INSTALL_INTERFACE:include/3rdparty/nghttp2>
)
target_compile_definitions(
  nghttp2.host PUBLIC -DNGHTTP2_STATICLIB -DHAVE_ARPA_INET_H=1
)
add_san(nghttp2.host)
set_property(TARGET nghttp2.host PROPERTY POSITION_INDEPENDENT_CODE ON)

if(INSTALL_VIRTUAL_LIBRARIES)
  install(
    TARGETS nghttp2.host
    EXPORT ccf
    DESTINATION lib
  )
endif()
