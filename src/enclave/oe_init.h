// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/enclave.h>
#else
#  include <openenclave/host_verify.h>
#endif

namespace ccf
{
  void initialize_oe()
  {
#if !defined(VIRTUAL_ENCLAVE)
    {
      auto rc = oe_attester_initialize();
      if (rc != OE_OK)
      {
        throw std::logic_error(fmt::format(
          "Failed to initialise evidence attester: {}", oe_result_str(rc)));
      }
    }
#endif
    {
      auto rc = oe_verifier_initialize();
      if (rc != OE_OK)
      {
        throw std::logic_error(fmt::format(
          "Failed to initialise evidence verifier: {}", oe_result_str(rc)));
      }
    }
  }

  void shutdown_oe()
  {
#if !defined(VIRTUAL_ENCLAVE)
    oe_attester_shutdown();
#endif
    oe_verifier_shutdown();
  }

}