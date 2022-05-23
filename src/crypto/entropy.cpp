// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/entropy.h"

#include "openssl/entropy.h"

namespace crypto
{
  EntropyPtr create_entropy()
  {
    if (use_drng)
    {
      if (!intel_drng_ptr)
        intel_drng_ptr = std::make_shared<IntelDRNG>();
      return intel_drng_ptr;
    }

    return std::make_shared<Entropy_OpenSSL>();
  }
}
