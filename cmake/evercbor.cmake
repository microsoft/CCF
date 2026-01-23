# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Build EverCBOR
set(EVERCBOR_DIR "${CCF_3RD_PARTY_INTERNAL_DIR}/evercbor")
set(EVERCBOR_SRCS "${EVERCBOR_DIR}/CBORNondet.c")

add_library(evercbor STATIC ${EVERCBOR_SRCS})

target_include_directories(
  evercbor PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_INTERNAL_DIR}/evercbor>
)

target_compile_options(evercbor PRIVATE -Wno-everything)
set_property(TARGET evercbor PROPERTY POSITION_INDEPENDENT_CODE ON)
add_san(evercbor)

install(
  TARGETS evercbor
  EXPORT ccf
  DESTINATION lib
)
