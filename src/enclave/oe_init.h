// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/enclave.h>
#elif !defined(DISABLE_OE)
#  include <openenclave/host_verify.h>
#endif
#include "ds/ccf_exception.h"

namespace ccf
{
  void initialize_oe()
  {
#if !defined(VIRTUAL_ENCLAVE)
    {
      auto rc = oe_attester_initialize();
      if (rc != OE_OK)
      {
        throw ccf::ccf_oe_attester_init_error(fmt::format(
          "Failed to initialise evidence attester: {}", oe_result_str(rc)));
      }
    }
#endif
#if !defined(DISABLE_OE)
    {
      auto rc = oe_verifier_initialize();
      if (rc != OE_OK)
      {
        throw ccf::ccf_oe_verifier_init_error(fmt::format(
          "Failed to initialise evidence verifier: {}", oe_result_str(rc)));
      }
    }
#endif
  }

  void shutdown_oe()
  {
#if !defined(VIRTUAL_ENCLAVE)
    oe_attester_shutdown();
#endif
#if !defined(DISABLE_OE)
    oe_verifier_shutdown();
#endif
  }

}