# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Path prefix to the QuickJS library source directory
set(QUICKJS_PREFIX ${CCF_3RD_PARTY_EXPORTED_DIR}/quickjs)

find_program(PATCH_EXECUTABLE patch REQUIRED)
set(
  QUICKJS_PATCH_DIR
  ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/patches/quickjs-2026-06-04
)
set(
  QUICKJS_BACKTRACE_PATCH
  ${QUICKJS_PATCH_DIR}/0001-retain-exception-during-backtrace.patch
)
set(
  QUICKJS_HEAP_LIMIT_PATCH
  ${QUICKJS_PATCH_DIR}/0002-enforce-lowered-heap-limit.patch
)
# Mirror the source prefix (3rdparty/exported/quickjs) under the build
# directory so that the generated, patched quickjs.c still matches the
# path-based sanitizer suppressions in src/san_common.suppressions.
set(QUICKJS_PATCHED_DIR ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/exported/quickjs)
set(QUICKJS_PATCHED_SOURCE ${QUICKJS_PATCHED_DIR}/quickjs.c)
add_custom_command(
  OUTPUT ${QUICKJS_PATCHED_SOURCE}
  BYPRODUCTS ${QUICKJS_PATCHED_SOURCE}.backtrace
  COMMAND ${CMAKE_COMMAND} -E make_directory ${QUICKJS_PATCHED_DIR}
  COMMAND
    ${PATCH_EXECUTABLE} --batch --forward --fuzz=0 --output
    ${QUICKJS_PATCHED_SOURCE}.backtrace ${QUICKJS_PREFIX}/quickjs.c
    ${QUICKJS_BACKTRACE_PATCH}
  COMMAND
    ${PATCH_EXECUTABLE} --batch --forward --fuzz=0 --output
    ${QUICKJS_PATCHED_SOURCE}.tmp ${QUICKJS_PATCHED_SOURCE}.backtrace
    ${QUICKJS_HEAP_LIMIT_PATCH}
  COMMAND
    ${CMAKE_COMMAND} -E rename ${QUICKJS_PATCHED_SOURCE}.tmp
    ${QUICKJS_PATCHED_SOURCE}
  DEPENDS
    ${QUICKJS_PREFIX}/quickjs.c
    ${QUICKJS_BACKTRACE_PATCH}
    ${QUICKJS_HEAP_LIMIT_PATCH}
  COMMENT "Applying local QuickJS patches"
  VERBATIM
)

set(
  QUICKJS_SRC
  ${QUICKJS_PREFIX}/cutils.c
  ${QUICKJS_PREFIX}/dtoa.c
  ${QUICKJS_PREFIX}/libunicode.c
  ${QUICKJS_PREFIX}/libregexp.c
  ${QUICKJS_PATCHED_SOURCE}
)
set_source_files_properties(
  ${QUICKJS_PATCHED_SOURCE}
  PROPERTIES COMPILE_FLAGS -Wno-implicit-int-float-conversion
)

execute_process(
  COMMAND cat "${QUICKJS_PREFIX}/VERSION"
  OUTPUT_VARIABLE QUICKJS_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "QuickJS prefix: ${QUICKJS_PREFIX} version: ${QUICKJS_VERSION}")

add_library(quickjs STATIC ${QUICKJS_SRC})
target_compile_options(
  quickjs
  PUBLIC -DCONFIG_VERSION="${QUICKJS_VERSION}"
  PRIVATE $<$<CONFIG:Debug>:-DDUMP_LEAKS>
)
add_san(quickjs)
add_hardening(quickjs)
set_property(TARGET quickjs PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(
  quickjs
  PUBLIC
    $<BUILD_INTERFACE:${CCF_3RD_PARTY_EXPORTED_DIR}/quickjs>
    $<INSTALL_INTERFACE:include/3rdparty/quickjs>
)

install(TARGETS quickjs EXPORT ccf DESTINATION lib)
