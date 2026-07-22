# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CCF_RS_DIR "${CCF_DIR}/src/rust")
set(CCF_RS_MANIFEST_PATH "${CCF_RS_DIR}/Cargo.toml")
set(CCF_RS_PACKAGE "ccf-rs")
set(CCF_RS_LIB "libccf_rs.a")
set(CCF_RS_LIB_BUILD_PATH "${CMAKE_BINARY_DIR}/${CCF_RS_LIB}")
set(CCF_RS_CARGO_TARGET_DIR "${CMAKE_BINARY_DIR}/cargo/build")

find_program(CARGO NAMES cargo REQUIRED)
find_program(RUSTC NAMES rustc REQUIRED)

# Multi-config generators (Visual Studio, Xcode, Ninja Multi-Config) choose the
# build type at build time, but Cargo profile selection happens at configure
# time. Reject them so the Rust library is never silently built with the wrong
# profile.
if(CMAKE_CONFIGURATION_TYPES)
  message(
    FATAL_ERROR
    "Multi-config generators are not supported for the Rust ccf-rs build. "
    "Use a single-config generator (e.g. -GNinja) and set CMAKE_BUILD_TYPE instead."
  )
endif()

# Map CMAKE_BUILD_TYPE to a Cargo profile. Debug uses the Cargo dev profile for
# faster compilation; all other build types use the release profile with LTO.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CCF_RS_CARGO_PROFILE_FLAG "")
  set(CCF_RS_CARGO_PROFILE_DIR "debug")
  set(CCF_RS_CARGO_PROFILE_NAME "dev")
else()
  set(CCF_RS_CARGO_PROFILE_FLAG "--release")
  set(CCF_RS_CARGO_PROFILE_DIR "release")
  set(CCF_RS_CARGO_PROFILE_NAME "release")
endif()

message(
  STATUS
  "Rust ccf-rs: CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -> Cargo profile '${CCF_RS_CARGO_PROFILE_NAME}'"
)

# This path depends on Cargo's default host-layout target/<profile> path. CMake
# intentionally reruns Cargo and lets Cargo decide whether the Rust inputs are dirty.
set(
  CCF_RS_CARGO_LIB_PATH
  "${CCF_RS_CARGO_TARGET_DIR}/${CCF_RS_CARGO_PROFILE_DIR}/${CCF_RS_LIB}"
)

# Reproducible builds: remap absolute paths in the binary. RUSTFLAGS applies to
# all crates, including dependencies.
set(
  CCF_RS_RUSTFLAGS
  "--remap-path-prefix=${CCF_DIR}=CCF --remap-path-prefix=$ENV{HOME}/.cargo=CARGO"
)

add_custom_target(
  cargo-build_ccf_rs
  BYPRODUCTS "${CCF_RS_LIB_BUILD_PATH}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${CCF_RS_CARGO_TARGET_DIR}"
  COMMAND
    "${CMAKE_COMMAND}" -E env --unset=CARGO_BUILD_TARGET
    "RUSTFLAGS=${CCF_RS_RUSTFLAGS}" "CARGO_NET_RETRY=10" "CARGO_HTTP_TIMEOUT=60"
    "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}" "AR=${CMAKE_AR}"
    "CARGO_BUILD_RUSTC=${RUSTC}" "${CARGO}" build --lib --package
    "${CCF_RS_PACKAGE}" --manifest-path "${CCF_RS_MANIFEST_PATH}" --target-dir
    "${CCF_RS_CARGO_TARGET_DIR}" ${CCF_RS_CARGO_PROFILE_FLAG} --locked
  COMMAND
    "${CMAKE_COMMAND}" -E copy_if_different "${CCF_RS_CARGO_LIB_PATH}"
    "${CMAKE_BINARY_DIR}"
  WORKING_DIRECTORY "${CCF_RS_DIR}"
  DEPENDS
    "${CCF_RS_MANIFEST_PATH}"
    "${CCF_RS_DIR}/Cargo.lock"
    "${CCF_RS_DIR}/rust-toolchain.toml"
    "${CCF_DIR}/src/cose/cose_rs/Cargo.toml"
    "${CCF_DIR}/3rdparty/internal/cose-openssl/Cargo.toml"
  COMMENT
    "Building ${CCF_RS_PACKAGE} Rust static library (Cargo profile: ${CCF_RS_CARGO_PROFILE_NAME})"
  USES_TERMINAL
  VERBATIM
)

install(FILES "${CCF_RS_LIB_BUILD_PATH}" DESTINATION lib)
