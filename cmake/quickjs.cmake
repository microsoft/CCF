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
  QUICKJS_PATCHES
  ${QUICKJS_PATCH_DIR}/0001-free-backtrace-buffer.patch
  ${QUICKJS_PATCH_DIR}/0002-enforce-lowered-heap-limit.patch
  ${QUICKJS_PATCH_DIR}/0003-commit-growable-shared-array-buffer.patch
)
# Mirror the source prefix (3rdparty/exported/quickjs) under the build
# directory so that the generated, patched quickjs.c still matches the
# path-based sanitizer suppressions in src/san_common.suppressions.
set(QUICKJS_PATCHED_DIR ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/exported/quickjs)
set(QUICKJS_PATCHED_SOURCE ${QUICKJS_PATCHED_DIR}/quickjs.c)
# Apply the patches in order, each to the output of the previous one.
set(QUICKJS_PATCH_COMMANDS "")
set(QUICKJS_PATCH_BYPRODUCTS "")
set(QUICKJS_PATCH_INPUT ${QUICKJS_PREFIX}/quickjs.c)
set(QUICKJS_PATCH_INDEX 0)
foreach(QUICKJS_PATCH IN LISTS QUICKJS_PATCHES)
  math(EXPR QUICKJS_PATCH_INDEX "${QUICKJS_PATCH_INDEX} + 1")
  set(QUICKJS_PATCH_OUTPUT ${QUICKJS_PATCHED_SOURCE}.${QUICKJS_PATCH_INDEX})
  list(
    APPEND QUICKJS_PATCH_COMMANDS
    COMMAND
    ${PATCH_EXECUTABLE}
    --batch
    --forward
    --fuzz=0
    --output
    ${QUICKJS_PATCH_OUTPUT}
    ${QUICKJS_PATCH_INPUT}
    ${QUICKJS_PATCH}
  )
  list(APPEND QUICKJS_PATCH_BYPRODUCTS ${QUICKJS_PATCH_OUTPUT})
  set(QUICKJS_PATCH_INPUT ${QUICKJS_PATCH_OUTPUT})
endforeach()
add_custom_command(
  OUTPUT ${QUICKJS_PATCHED_SOURCE}
  BYPRODUCTS ${QUICKJS_PATCH_BYPRODUCTS}
  COMMAND
    ${CMAKE_COMMAND} -E make_directory ${QUICKJS_PATCHED_DIR}
    ${QUICKJS_PATCH_COMMANDS}
  COMMAND
    ${CMAKE_COMMAND} -E copy ${QUICKJS_PATCH_INPUT} ${QUICKJS_PATCHED_SOURCE}
  DEPENDS ${QUICKJS_PREFIX}/quickjs.c ${QUICKJS_PATCHES}
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
# Upstream only changes VERSION on release, but the bytecode format can change
# between releases. When the manifest pins an untagged snapshot, append its
# commit so that bytecode cached by another snapshot is not loaded.
set(QUICKJS_MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/cgmanifest.json)
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS ${QUICKJS_MANIFEST}
)
file(READ ${QUICKJS_MANIFEST} QUICKJS_MANIFEST_JSON)
string(
  JSON QUICKJS_REGISTRATION_COUNT
  LENGTH "${QUICKJS_MANIFEST_JSON}"
  Registrations
)
math(EXPR QUICKJS_LAST_REGISTRATION "${QUICKJS_REGISTRATION_COUNT} - 1")
set(QUICKJS_COMMIT "")
foreach(QUICKJS_INDEX RANGE ${QUICKJS_LAST_REGISTRATION})
  string(
    JSON QUICKJS_REGISTRATION_URL
    ERROR_VARIABLE QUICKJS_JSON_ERROR
    GET "${QUICKJS_MANIFEST_JSON}"
    Registrations
    ${QUICKJS_INDEX}
    component
    git
    repositoryUrl
  )
  if(QUICKJS_REGISTRATION_URL STREQUAL "https://github.com/bellard/quickjs")
    string(
      JSON QUICKJS_COMMIT
      GET "${QUICKJS_MANIFEST_JSON}"
      Registrations
      ${QUICKJS_INDEX}
      component
      git
      commitHash
    )
    string(
      JSON QUICKJS_TAG
      ERROR_VARIABLE QUICKJS_TAG_ERROR
      GET "${QUICKJS_MANIFEST_JSON}"
      Registrations
      ${QUICKJS_INDEX}
      component
      git
      tag
    )
    break()
  endif()
endforeach()
if(NOT QUICKJS_COMMIT MATCHES "^[0-9a-f]+$")
  message(FATAL_ERROR "No QuickJS commit found in ${QUICKJS_MANIFEST}")
endif()
if(QUICKJS_TAG_ERROR)
  string(SUBSTRING "${QUICKJS_COMMIT}" 0 12 QUICKJS_SHORT_COMMIT)
  string(APPEND QUICKJS_VERSION "-${QUICKJS_SHORT_COMMIT}")
endif()
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
