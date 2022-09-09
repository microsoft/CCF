# Build QCBOR
set(QCBOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/internal/QCBOR")
set(QCBOR_SRC "${QCBOR_DIR}/src")
set(QCBOR_INC "${QCBOR_DIR}/inc")
set(QCBOR_SRCS
  "${QCBOR_SRC}/ieee754.c"
  "${QCBOR_SRC}/qcbor_decode.c"
  "${QCBOR_SRC}/qcbor_encode.c"
  "${QCBOR_SRC}/qcbor_err_to_str.c"
  "${QCBOR_SRC}/UsefulBuf.c"
)
if ("sgx" IN_LIST COMPILE_TARGETS)
  add_enclave_library_c(qcbor.enclave ${QCBOR_SRCS})
  target_include_directories(qcbor.enclave PUBLIC "${QCBOR_INC}")
endif()
if ("virtual" IN_LIST COMPILE_TARGETS)
  add_library(qcbor.virtual STATIC ${QCBOR_SRCS})
  target_include_directories(qcbor.virtual PUBLIC "${QCBOR_INC}")
  set_property(TARGET qcbor.virtual PROPERTY POSITION_INDEPENDENT_CODE ON)
  add_san(qcbor.virtual)
endif()