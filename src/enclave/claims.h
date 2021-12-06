// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash_provider.h"

namespace ccf
{
  class ClaimsDigest
  {
  public:
    using Digest = crypto::Sha256Hash; 

  private:
    bool is_set = false;
    Digest digest;

  public:
    ClaimsDigest() = default;

    inline void set(const Digest& digest_) // TODO: move?
    {
      is_set = true;
      digest = digest_;
    }

    inline bool empty() const
    {
      return is_set;
    }

    const Digest& value() const
    {
      return digest;
    }
  };

  static ClaimsDigest no_claims()
  {
    return ClaimsDigest();
  }
}