# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

corrosion_import_crate(
  MANIFEST_PATH
  "${CCF_DIR}/src/cose/cose_rs/Cargo.toml"
  PROFILE
  "release"
  CRATES
  "cose-rs"
  CRATE_TYPES
  "staticlib"
)

# Reproducible builds: remap absolute paths in the binary. RUSTFLAGS applies to
# all crates (including dependencies), unlike
# corrosion_add_target_local_rustflags which only applies to the top crate.
corrosion_set_env_vars(
  cose_rs
  "RUSTFLAGS=--remap-path-prefix=${CCF_DIR}=CCF --remap-path-prefix=$ENV{HOME}/.cargo=CARGO"
)

# What Rust, and therefore corrosion defaults to.
set(COSE_RS_LIB libcose_rs.a)

install(FILES ${CMAKE_BINARY_DIR}/${COSE_RS_LIB} DESTINATION lib)
