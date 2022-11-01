# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(QUICKJS_PREFIX
    ${CCF_3RD_PARTY_EXPORTED_DIR}/quickjs
    CACHE PATH "Prefix to the QuickJS library"
)

set(QUICKJS_INC ${QUICKJS_PREFIX})

set(QUICKJS_SRC
    ${QUICKJS_PREFIX}/cutils.c ${QUICKJS_PREFIX}/libbf.c
    ${QUICKJS_PREFIX}/libunicode.c ${QUICKJS_PREFIX}/libregexp.c
    ${QUICKJS_PREFIX}/quickjs.c
)
set_source_files_properties(
  ${QUICKJS_PREFIX}/quickjs.c PROPERTIES COMPILE_FLAGS
                                         -Wno-implicit-int-float-conversion
)

execute_process(
  COMMAND cat "${QUICKJS_PREFIX}/VERSION"
  OUTPUT_VARIABLE QUICKJS_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "QuickJS prefix: ${QUICKJS_PREFIX} version: ${QUICKJS_VERSION}")

# We need two versions of libquickjs, because it depends on libc

if(COMPILE_TARGET STREQUAL "sgx")
  add_enclave_library_c(quickjs.enclave ${QUICKJS_SRC})
  target_compile_options(
    quickjs.enclave
    PUBLIC -DCONFIG_VERSION="${QUICKJS_VERSION}" -DEMSCRIPTEN
           -DCONFIG_STACK_CHECK -DCONFIG_BIGNUM
    PRIVATE $<$<CONFIG:Debug>:-DDUMP_LEAKS>
  )
  target_include_directories(
    quickjs.enclave
    PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_EXPORTED_DIR}/quickjs>
           $<INSTALL_INTERFACE:include/3rdparty/quickjs>
  )

  install(
    TARGETS quickjs.enclave
    EXPORT ccf
    DESTINATION lib
  )
endif()

add_library(quickjs.host STATIC ${QUICKJS_SRC})
target_compile_options(
  quickjs.host
  PUBLIC -DCONFIG_VERSION="${QUICKJS_VERSION}" -DCONFIG_BIGNUM
  PRIVATE $<$<CONFIG:Debug>:-DDUMP_LEAKS>
)
add_san(quickjs.host)
set_property(TARGET quickjs.host PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(
  quickjs.host PUBLIC $<BUILD_INTERFACE:${CCF_3RD_PARTY_EXPORTED_DIR}/quickjs>
                      $<INSTALL_INTERFACE:include/3rdparty/quickjs>
)

if(INSTALL_VIRTUAL_LIBRARIES)
  install(
    TARGETS quickjs.host
    EXPORT ccf
    DESTINATION lib
  )
endif()
