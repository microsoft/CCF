# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# We allow for Open Enclave (and Open Enclave HostVerify) to _not_ be installed,
# with some limitations (e.g. virtual/snp builds cannot verify sgx attestation
# reports). This can hopefully be removed by 5.x (see
# https://github.com/microsoft/CCF/issues/5291).
option(REQUIRE_OPENENCLAVE "Requires Open Enclave or HostVerify variant" ON)

if(REQUIRE_OPENENCLAVE)
  if(NOT COMPILE_TARGET STREQUAL "sgx")
    set(COMPONENT "OEHOSTVERIFY")
  endif()

  # Find OpenEnclave package
  find_package(OpenEnclave 0.19.13 CONFIG REQUIRED)

  option(USE_OPENSSL_3 "Use OpenSSL 3.x for Open Enclave builds" ON)
  if(USE_OPENSSL_3)
    set(OE_OPENSSL_LIBRARY openenclave::oecryptoopenssl_3)
  else()
    set(OE_OPENSSL_LIBRARY openenclave::oecryptoopenssl)
  endif()
  # As well as pulling in openenclave:: targets, this sets variables which can
  # be used for our edge cases (eg - for virtual libraries). These do not follow
  # the standard naming patterns, for example use OE_INCLUDEDIR rather than
  # OpenEnclave_INCLUDE_DIRS
  if(COMPILE_TARGET STREQUAL "sgx")
    set(OE_TARGET_LIBC openenclave::oelibc)
    set(OE_TARGET_ENCLAVE_AND_STD openenclave::oeenclave openenclave::oelibcxx
                                  openenclave::oelibc ${OE_OPENSSL_LIBRARY}
    )

    # These oe libraries must be linked in specific order
    set(OE_TARGET_ENCLAVE_CORE_LIBS
        openenclave::oeenclave openenclave::oesnmalloc openenclave::oecore
        openenclave::oesyscall
    )

    option(LVI_MITIGATIONS "Enable LVI mitigations" ON)
    if(LVI_MITIGATIONS)
      string(APPEND OE_TARGET_LIBC -lvi-cfg)
      list(TRANSFORM OE_TARGET_ENCLAVE_AND_STD APPEND -lvi-cfg)
      list(TRANSFORM OE_TARGET_ENCLAVE_CORE_LIBS APPEND -lvi-cfg)
    endif()

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
elseif(COMPILE_TARGET STREQUAL "sgx")
  message(FATAL_ERROR "Open Enclave is required for SGX target")
endif()

function(link_openenclave_host name)
  if(REQUIRE_OPENENCLAVE)
    target_link_libraries(${name} PUBLIC ${OE_HOST_LIBRARY})
    target_compile_definitions(${name} PUBLIC SGX_ATTESTATION_VERIFICATION)
  endif()
endfunction()
