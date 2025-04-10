// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/entropy.h"

#include "openssl/entropy.h"

namespace ccf::crypto
{
  EntropyPtr get_entropy()
  {
    return std::make_shared<Entropy_OpenSSL>();
  }
}
