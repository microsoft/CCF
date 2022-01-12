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

    inline void set(Digest&& digest_)
    {
      is_set = true;
      digest = std::move(digest_);
    }

    inline void set(Digest::Representation&& r)
    {
      is_set = true;
      digest.set(std::move(r));
    }

    inline bool empty() const
    {
      return !is_set;
    }

    const Digest& value() const
    {
      return digest;
    }

    bool operator==(const ClaimsDigest& other) const
    {
      return (is_set == other.is_set) && (digest == other.digest);
    }
  };
}