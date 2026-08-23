# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Enclave library wrapper
function(add_ccf_app name)
  cmake_parse_arguments(
    PARSE_ARGV 1
    PARSED_ARGS
    ""
    ""
    "SRCS;INCLUDE_DIRS;SYSTEM_INCLUDE_DIRS;LINK_LIBS;DEPS;INSTALL_LIBS"
  )

  # Build app executable
  add_executable(${name} ${PARSED_ARGS_SRCS})

  target_include_directories(${name} PRIVATE ${PARSED_ARGS_INCLUDE_DIRS})
  target_include_directories(
    ${name}
    SYSTEM
    PRIVATE ${PARSED_ARGS_SYSTEM_INCLUDE_DIRS}
  )
  add_warning_checks(${name})

  target_link_libraries(
    ${name}
    PRIVATE ${PARSED_ARGS_LINK_LIBS} ccf_launcher ccf
  )

  if(NOT (SAN OR TSAN))
    target_link_options(${name} PRIVATE LINKER:--no-undefined)
  endif()

  set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)

  add_san(${name})
  add_hardening(${name})
  add_tidy(${name})
  enable_coverage(${name})

  if(USE_SNMALLOC)
    target_link_libraries(${name} INTERFACE snmallocshim-static)
  endif()

  add_dependencies(${name} ${name})
  if(PARSED_ARGS_DEPS)
    add_dependencies(${name} ${PARSED_ARGS_DEPS})
  endif()

  if(${PARSED_ARGS_INSTALL_LIBS})
    install(TARGETS ${name} DESTINATION bin)
  endif()
endfunction()

function(add_ccf_rust_app name)
  cmake_parse_arguments(
    PARSE_ARGV 1
    PARSED_ARGS
    ""
    "MANIFEST_PATH;PACKAGE"
    "DEPS"
  )

  if(NOT PARSED_ARGS_MANIFEST_PATH)
    message(FATAL_ERROR "add_ccf_rust_app requires MANIFEST_PATH")
  endif()
  if(NOT PARSED_ARGS_PACKAGE)
    set(PARSED_ARGS_PACKAGE ${name})
  endif()

  find_program(CARGO NAMES cargo REQUIRED)
  find_program(RUSTC NAMES rustc REQUIRED)

  if(CMAKE_CONFIGURATION_TYPES)
    message(
      FATAL_ERROR
      "Multi-config generators are not supported for Rust CCF applications"
    )
  endif()

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_PROFILE_FLAG "")
    set(CARGO_PROFILE_DIR debug)
  else()
    set(CARGO_PROFILE_FLAG --release)
    set(CARGO_PROFILE_DIR release)
  endif()

  string(REPLACE "-" "_" RUST_LIB_NAME ${PARSED_ARGS_PACKAGE})
  get_filename_component(MANIFEST_PATH ${PARSED_ARGS_MANIFEST_PATH} ABSOLUTE)
  get_filename_component(MANIFEST_DIR ${MANIFEST_PATH} DIRECTORY)
  set(CARGO_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/cargo/${name})
  set(
    RUST_APP_LIB
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE_DIR}/lib${RUST_LIB_NAME}.a
  )

  file(GLOB_RECURSE RUST_APP_SOURCES CONFIGURE_DEPENDS ${MANIFEST_DIR}/src/*.rs)

  set(
    RUSTFLAGS
    "$ENV{RUSTFLAGS} --remap-path-prefix=${MANIFEST_DIR}=APP --remap-path-prefix=${CCF_DIR}=CCF --remap-path-prefix=$ENV{HOME}/.cargo=CARGO"
  )
  add_custom_command(
    OUTPUT ${RUST_APP_LIB}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CARGO_TARGET_DIR}
    COMMAND
      ${CMAKE_COMMAND} -E env --unset=CARGO_BUILD_TARGET
      "RUSTFLAGS=${RUSTFLAGS}" "CARGO_NET_RETRY=10" "CARGO_HTTP_TIMEOUT=60"
      "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}" "AR=${CMAKE_AR}"
      "CARGO_BUILD_RUSTC=${RUSTC}" ${CARGO} build --lib --package
      ${PARSED_ARGS_PACKAGE} --manifest-path ${MANIFEST_PATH} --target-dir
      ${CARGO_TARGET_DIR} ${CARGO_PROFILE_FLAG} --locked
    WORKING_DIRECTORY ${MANIFEST_DIR}
    DEPENDS
      ${MANIFEST_PATH}
      ${MANIFEST_DIR}/Cargo.lock
      ${RUST_APP_SOURCES}
      ${PARSED_ARGS_DEPS}
    COMMENT "Building Rust CCF application ${name}"
    USES_TERMINAL
    VERBATIM
  )
  add_custom_target(cargo-build_${name} DEPENDS ${RUST_APP_LIB})

  if(EXISTS "${CCF_DIR}/src/rust/app_bridge.cpp")
    set(RUST_BRIDGE_SOURCE "${CCF_DIR}/src/rust/app_bridge.cpp")
    set(RUST_APP_MAIN_SOURCE "${CCF_DIR}/samples/apps/main.cpp")
  else()
    set(RUST_BRIDGE_SOURCE "${CCF_DIR}/share/ccf/rust/app_bridge.cpp")
    set(RUST_APP_MAIN_SOURCE "${CCF_DIR}/share/ccf/rust/app_main.cpp")
  endif()

  add_ccf_app(
    ${name}
    SRCS ${RUST_BRIDGE_SOURCE} ${RUST_APP_MAIN_SOURCE}
    LINK_LIBS ${RUST_APP_LIB}
    DEPS cargo-build_${name}
  )
endfunction()

function(add_ccf_static_library name)
  cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;LINK_LIBS")

  add_library(${name} STATIC ${PARSED_ARGS_SRCS})

  target_link_libraries(${name} PUBLIC ${PARSED_ARGS_LINK_LIBS})

  set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)

  add_san(${name})
  add_hardening(${name})
  add_tidy(${name})
  add_warning_checks(${name})

  install(TARGETS ${name} EXPORT ccf DESTINATION lib)

  if(USE_SNMALLOC)
    target_link_libraries(${name} INTERFACE snmallocshim-static)
  endif()
endfunction()
