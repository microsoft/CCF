# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(COSE_RS_DIR "${CCF_DIR}/src/cose/cose_rs")
set(COSE_RS_MANIFEST_PATH "${COSE_RS_DIR}/Cargo.toml")
set(COSE_RS_PACKAGE "cose-rs")
set(COSE_RS_LIB "libcose_rs.a")
set(COSE_RS_LIB_BUILD_PATH "${CMAKE_BINARY_DIR}/${COSE_RS_LIB}")
set(COSE_RS_CARGO_TARGET_DIR "${CMAKE_BINARY_DIR}/cargo/build")

find_program(CARGO NAMES cargo REQUIRED)
find_program(RUSTC NAMES rustc REQUIRED)

# This path depends on Cargo's default host-layout target/release path. CMake
# intentionally reruns Cargo and lets Cargo decide whether the Rust inputs are dirty.
set(COSE_RS_CARGO_LIB_PATH "${COSE_RS_CARGO_TARGET_DIR}/release/${COSE_RS_LIB}")

# Reproducible builds: remap absolute paths in the binary. RUSTFLAGS applies to
# all crates, including dependencies.
set(
  COSE_RS_RUSTFLAGS
  "--remap-path-prefix=${CCF_DIR}=CCF --remap-path-prefix=$ENV{HOME}/.cargo=CARGO"
)

add_custom_target(
  cargo-build_cose_rs
  BYPRODUCTS "${COSE_RS_LIB_BUILD_PATH}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${COSE_RS_CARGO_TARGET_DIR}"
  COMMAND
    "${CMAKE_COMMAND}" -E env --unset=CARGO_BUILD_TARGET
    "RUSTFLAGS=${COSE_RS_RUSTFLAGS}" "CC=${CMAKE_C_COMPILER}"
    "CXX=${CMAKE_CXX_COMPILER}" "AR=${CMAKE_AR}" "CARGO_BUILD_RUSTC=${RUSTC}"
    "${CARGO}" build --lib --package "${COSE_RS_PACKAGE}" --manifest-path
    "${COSE_RS_MANIFEST_PATH}" --target-dir "${COSE_RS_CARGO_TARGET_DIR}"
    --release
  COMMAND
    "${CMAKE_COMMAND}" -E copy_if_different "${COSE_RS_CARGO_LIB_PATH}"
    "${CMAKE_BINARY_DIR}"
  WORKING_DIRECTORY "${COSE_RS_DIR}"
  DEPENDS
    "${COSE_RS_MANIFEST_PATH}"
    "${COSE_RS_DIR}/Cargo.lock"
    "${COSE_RS_DIR}/rust-toolchain.toml"
    "${CCF_DIR}/3rdparty/internal/cose-openssl/Cargo.toml"
  COMMENT "Building ${COSE_RS_PACKAGE} Rust static library via Cargo"
  USES_TERMINAL
  VERBATIM
)

install(FILES "${COSE_RS_LIB_BUILD_PATH}" DESTINATION lib)
