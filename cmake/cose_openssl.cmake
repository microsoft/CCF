# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

include(FetchContent)

FetchContent_Declare(
  Corrosion
  GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
  GIT_TAG a1a1aaa057a5da656c06c3d8505b767a4e941709 # v0.5.2
)
FetchContent_MakeAvailable(Corrosion)

FetchContent_Declare(
  cose_openssl
  GIT_REPOSITORY https://github.com/maxtropets/cose-openssl.git
  GIT_TAG 312bb5f94d4e4241052df5d17cfdb51ef66fcea9
)
FetchContent_MakeAvailable(cose_openssl)

# The cose-openssl workspace patches cborrs to a local clone of everparse. Run
# the setup script so the .patched/ directory exists before cargo builds.
if(NOT EXISTS "${cose_openssl_SOURCE_DIR}/.patched/everparse")
  message(STATUS "Setting up everparse for cose-openssl ...")
  execute_process(
    COMMAND bash "${cose_openssl_SOURCE_DIR}/scripts/setup-everparse.sh"
    WORKING_DIRECTORY "${cose_openssl_SOURCE_DIR}"
    RESULT_VARIABLE _everparse_rc
  )
  if(NOT _everparse_rc EQUAL 0)
    message(FATAL_ERROR "setup-everparse.sh failed with rc=${_everparse_rc}")
  endif()
endif()

corrosion_import_crate(
  MANIFEST_PATH
  "${cose_openssl_SOURCE_DIR}/cose-openssl-ffi/Cargo.toml"
  PROFILE
  "release"
  CRATES
  "cose-openssl-ffi"
  CRATE_TYPES
  "staticlib"
)
