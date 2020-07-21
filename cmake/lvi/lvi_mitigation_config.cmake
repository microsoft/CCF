# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(NOT DEFINED OE_BINDIR)
  message(
    FATAL_ERROR
      "Open Enclave package must be found before configuring LVI mitigations"
  )
endif()

# Run OE script to create local binary directory (at configure time!)
set(LVI_MITIGATION_BINDIR ${CMAKE_CURRENT_BINARY_DIR}/lvi_mitigation_bin)
execute_process(
  COMMAND echo yes
  COMMAND ${OE_BINDIR}/scripts/lvi-mitigation/install_lvi_mitigation_bindir
  #ERROR_QUIET
)

# OE_LVI_MITIGATION holds the value of LVI_MITIGATION from the configuration of
# OE SDK. OE_LVI_MITIGATION=ControlFlow indicates that the SDK supports LVI
# mitigation.
set(OE_LVI_MITIGATION "ControlFlow")

# Include the helper function to apply lvi mitigation.
if(OE_LVI_MITIGATION MATCHES ControlFlow)
  if(UNIX)
    include("${CMAKE_CURRENT_LIST_DIR}/configure_lvi_mitigation_build.cmake")
    # Pick up the customized compilation toolchain based on the specified path.
    configure_lvi_mitigation_build(BINDIR ${LVI_MITIGATION_BINDIR} IN_PACKAGE)
  endif()
  include("${CMAKE_CURRENT_LIST_DIR}/apply_lvi_mitigation.cmake")
else()
  message(
    FATAL_ERROR
      "This version of the OE SDK was not built with support for LVI mitigation."
  )
endif()
