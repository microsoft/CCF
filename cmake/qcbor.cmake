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
if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library_c(qcbor.enclave ${QCBOR_SRCS})
  target_include_directories(
    qcbor.enclave PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_EXPORTED_DIR}/QCBOR>
                         $<INSTALL_INTERFACE:include/3rdparty/QCBOR>
  )

  install(
    TARGETS qcbor.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

add_library(qcbor.host STATIC ${QCBOR_SRCS})

target_include_directories(
  qcbor.host PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_EXPORTED_DIR}/QCBOR>
                    $<INSTALL_INTERFACE:include/3rdparty/QCBOR>
)
set_property(TARGET qcbor.host PROPERTY POSITION_INDEPENDENT_CODE ON)
add_san(qcbor.host)

if(INSTALL_VIRTUAL_LIBRARIES)
  install(
    TARGETS qcbor.host
    EXPORT ccf
    DESTINATION lib
  )
endif()
