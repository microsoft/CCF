# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Build QCBOR
set(QCBOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/exported/QCBOR")
set(QCBOR_SRC "${QCBOR_DIR}/src")
set(QCBOR_SRCS
    "${QCBOR_SRC}/ieee754.c" "${QCBOR_SRC}/qcbor_decode.c"
    "${QCBOR_SRC}/qcbor_encode.c" "${QCBOR_SRC}/qcbor_err_to_str.c"
    "${QCBOR_SRC}/UsefulBuf.c"
)

add_library(qcbor STATIC ${QCBOR_SRCS})

target_include_directories(
  qcbor PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_EXPORTED_DIR}/QCBOR/inc>
               $<INSTALL_INTERFACE:include/3rdparty/QCBOR/inc>
)
set_property(TARGET qcbor PROPERTY POSITION_INDEPENDENT_CODE ON)
add_san(qcbor)

install(
  TARGETS qcbor
  EXPORT ccf
  DESTINATION lib
)
