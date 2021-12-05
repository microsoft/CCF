// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash_provider.h"

namespace ccf
{
  class ClaimsDigest
  {
    bool is_set = false;
    crypto::Sha256Hash digest;

  public:
    ClaimsDigest() = default;

    inline void set(crypto::Sha256Hash digest_)
    {
      is_set = true;
      digest = digest_;
    }

    inline bool empty() const
    {
      return is_set;
    }

    const crypto::Sha256Hash& value() const
    {
      return digest;
    }
  };

  static ClaimsDigest no_claims()
  {
    return ClaimsDigest();
  }
}