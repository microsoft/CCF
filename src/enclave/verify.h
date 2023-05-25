// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/attestation/verifier.h>
#  include <openenclave/enclave.h>
#elif defined(SGX_ATTESTATION_VERIFICATION)
#  include <openenclave/host_verify.h>
#endif
#include "ccf/ds/ccf_exception.h"

namespace ccf
{
  void initialize_verifiers()
  {
#ifdef SGX_ATTESTATION_VERIFICATION
    auto rc = oe_verifier_initialize();
    if (rc != OE_OK)
    {
      throw ccf::ccf_oe_verifier_init_error(fmt::format(
        "Failed to initialise evidence verifier: {}", oe_result_str(rc)));
    }
#endif
  }

  void shutdown_verifiers()
  {
#ifdef SGX_ATTESTATION_VERIFICATION
    oe_verifier_shutdown();
#endif
  }
}