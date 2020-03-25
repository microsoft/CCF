# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(QUICKJS_PREFIX
    ${CCF_DIR}/3rdparty/quickjs
    CACHE PATH "Prefix to the QuickJS library"
)

set(QUICKJS_INC ${QUICKJS_PREFIX})

set(QUICKJS_SRC
    ${QUICKJS_PREFIX}/cutils.c ${QUICKJS_PREFIX}/libbf.c
    ${QUICKJS_PREFIX}/libunicode.c ${QUICKJS_PREFIX}/libregexp.c
    ${QUICKJS_PREFIX}/quickjs.c
)

execute_process(
  COMMAND cat "${QUICKJS_PREFIX}/VERSION"
  OUTPUT_VARIABLE QUICKJS_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "QuickJS prefix: ${QUICKJS_PREFIX} version: ${QUICKJS_VERSION}")

# We need two versions of libquickjs, because it depends on libc

if("sgx" IN_LIST COMPILE_TARGETS)
  add_library(
    quickjs.enclave STATIC ${QUICKJS_SRC} ${CCF_DIR}/3rdparty/stub/stub.c
  )
  target_compile_options(
    quickjs.enclave PUBLIC -nostdinc -DCONFIG_VERSION="${QUICKJS_VERSION}"
                           -DEMSCRIPTEN
  )
  target_link_libraries(quickjs.enclave PUBLIC openenclave::oelibc)
  set_property(TARGET quickjs.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(quickjs.enclave PUBLIC ${QUICKJS_INC})

  install(TARGETS quickjs.enclave DESTINATION lib)
endif()

add_library(quickjs.host STATIC ${QUICKJS_SRC})
target_compile_options(
  quickjs.host PUBLIC -DCONFIG_VERSION="${QUICKJS_VERSION}"
)
set_property(TARGET quickjs.host PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(quickjs.host PUBLIC ${QUICKJS_INC})

install(TARGETS quickjs.host DESTINATION lib)
