# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(NOT COMPILE_TARGET STREQUAL "sgx")
  set(COMPONENT "OEHOSTVERIFY")
endif()

# Find OpenEnclave package
find_package(OpenEnclave 0.19.3 CONFIG REQUIRED)
# As well as pulling in openenclave:: targets, this sets variables which can be
# used for our edge cases (eg - for virtual libraries). These do not follow the
# standard naming patterns, for example use OE_INCLUDEDIR rather than
# OpenEnclave_INCLUDE_DIRS

if(COMPILE_TARGET STREQUAL "sgx")
  set(OE_TARGET_LIBC openenclave::oelibc)
  set(OE_TARGET_ENCLAVE_AND_STD
      openenclave::oeenclave openenclave::oelibcxx openenclave::oelibc
      openenclave::oecryptoopenssl
  )
  # These oe libraries must be linked in specific order
  set(OE_TARGET_ENCLAVE_CORE_LIBS
      openenclave::oeenclave openenclave::oesnmalloc openenclave::oecore
      openenclave::oesyscall
  )

  option(LVI_MITIGATIONS "Enable LVI mitigations" ON)

  function(add_lvi_mitigations name)
    if(LVI_MITIGATIONS)
      # Enable clang-11 built-in LVI mitigation
      target_compile_options(${name} PRIVATE -mlvi-cfi)
    endif()
  endfunction()

  set(OE_HOST_LIBRARY openenclave::oehost)
else()
  set(OE_HOST_LIBRARY openenclave::oehostverify)
endif()
