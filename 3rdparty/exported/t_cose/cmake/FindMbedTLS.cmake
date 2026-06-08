#[=======================================================================[.rst:
FindMbedTLS
-------

Finds the mbedTLS library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``MbedTLS::MbedTLS``
  The mbedTLS library

``MbedTLS::MbedCrypto``
  The mbedTLS crypto library

``MbedTLS::MbedX509``
  The mbedTLS X509 library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``MbedTLS_FOUND``
  True if the system has the MbedTLS library.
``MbedTLS_INCLUDE_DIRS``
  Include directories needed to use MbedTLS.
``MbedTLS_LIBRARIES``
  Libraries needed to link to MbedTLS.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``MbedTLS_INCLUDE_DIR``
  The directory containing ``mbedtls/``.
``MbedTLS_LIBRARY``
  The path to the mbedtls library.
``MbedTLS_CRYPTO_LIBRARY``
  The path to the mbedcrypto library.
``MbedTLS_X509_LIBRARY``
  The path to the mbedx509 library.

#]=======================================================================]

find_path(MbedTLS_INCLUDE_DIR
  NAMES mbedtls/version.h
)
find_library(MbedTLS_LIBRARY
  NAMES mbedtls
)
find_library(MbedTLS_CRYPTO_LIBRARY
  NAMES mbedcrypto
)
find_library(MbedTLS_X509_LIBRARY
  NAMES mbedx509
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
  FOUND_VAR MbedTLS_FOUND
  REQUIRED_VARS
    MbedTLS_LIBRARY
    MbedTLS_CRYPTO_LIBRARY
    MbedTLS_X509_LIBRARY
    MbedTLS_INCLUDE_DIR
)

if(MbedTLS_FOUND)
  set(MbedTLS_LIBRARIES "${MbedTLS_LIBRARY}" "${MbedTLS_X509_LIBRARY}" "${MbedTLS_CRYPTO_LIBRARY}")
  set(MbedTLS_INCLUDE_DIRS "${MbedTLS_INCLUDE_DIR}")
endif()

if(MbedTLS_FOUND AND NOT TARGET MbedTLS::MbedCrypto)
  add_library(MbedTLS::MbedCrypto UNKNOWN IMPORTED)
  set_target_properties(MbedTLS::MbedCrypto PROPERTIES
    IMPORTED_LOCATION "${MbedTLS_CRYPTO_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
  )
endif()

if(MbedTLS_FOUND AND NOT TARGET MbedTLS::MbedX509)
  add_library(MbedTLS::MbedX509 UNKNOWN IMPORTED)
  set_target_properties(MbedTLS::MbedX509 PROPERTIES
    IMPORTED_LOCATION "${MbedTLS_X509_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
  )
  target_link_libraries(MbedTLS::MbedX509 INTERFACE MbedTLS::MbedCrypto)
endif()

if(MbedTLS_FOUND AND NOT TARGET MbedTLS::MbedTLS)
  add_library(MbedTLS::MbedTLS UNKNOWN IMPORTED)
  set_target_properties(MbedTLS::MbedTLS PROPERTIES
    IMPORTED_LOCATION "${MbedTLS_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
  )
  target_link_libraries(MbedTLS::MbedX509 INTERFACE MbedTLS::MbedCrypto MbedTLS::MbedX509)
endif()

mark_as_advanced(
  MbedTLS_INCLUDE_DIR
  MbedTLS_LIBRARY
  MbedTLS_CRYPTO_LIBRARY
  MbedTLS_X509_LIBRARY
)
