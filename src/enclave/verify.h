// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/attestation/verifier.h>
#  include <openenclave/enclave.h>
#else
#  include <openenclave/host_verify.h>
#endif
#include "ccf/ds/ccf_exception.h"

namespace ccf
{
  void initialize_verifiers()
  {
    auto rc = oe_verifier_initialize();
    if (rc != OE_OK)
    {
      throw ccf::ccf_oe_verifier_init_error(fmt::format(
        "Failed to initialise evidence verifier: {}", oe_result_str(rc)));
    }
  }

  void shutdown_verifiers()
  {
    oe_verifier_shutdown();
  }
}