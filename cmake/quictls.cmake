# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

option(ENABLE_QUICTLS "Enable QUICTLS inside virtual enclave" OFF)
if(ENABLE_QUICTLS)
  message(STATUS "WARNING: QUIC utilisation is experimental")

  # This isn't a good place, but because we're using the Universal Package to
  # download it before the build directory is created, and all CI scripts are
  # set with -xe, the `mkdir build` will fail in a later stage (and we don't
  # want to use -p in case there is a build dir from a previous build). This
  # will need to be fixed once we start using QUIC and shipping those libraries
  # with CCF
  set(QUICTLS_PATH ${CMAKE_SOURCE_DIR}/build-quictls)

  if(NOT EXISTS ${QUICTLS_PATH})
    message(
      FATAL_ERROR
        "ERROR: QUIC OpenSSL build not available, fetch it from the Azure Universal Package and add it to ${CMAKE_SOURCE_DIR}/build-quictls"
    )
  endif()

  find_path(QUICTLS_INCLUDE_DIRS openssl/ssl.h HINTS ${QUICTLS_PATH}/include)

  # This is intentionally different to override OE's libraries with our own
  find_library(QUICTLS_SSL_LIBRARY ssl HINTS ${QUICTLS_PATH}/lib)
  find_library(QUICTLS_CRYPTO_LIBRARY crypto HINTS ${QUICTLS_PATH}/lib)

  set(QUICTLS_LIBRARIES "${QUICTLS_SSL_LIBRARY}" "${QUICTLS_CRYPTO_LIBRARY}")
endif()
