// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/claims_digest.h"
#include "ds/logger.h"

namespace ccf
{
  static ClaimsDigest no_claims()
  {
    return ClaimsDigest();
  }

  static crypto::Sha256Hash entry_leaf(
    const std::vector<uint8_t>& write_set,
    const std::optional<crypto::Sha256Hash>& commit_evidence_digest,
    const ClaimsDigest& claims_digest)
  {
    crypto::Sha256Hash write_set_digest({write_set.data(), write_set.size()});
    if (commit_evidence_digest.has_value())
    {
      if (claims_digest.empty())
      {
        return crypto::Sha256Hash(
          write_set_digest, commit_evidence_digest.value());
      }
      else
      {
        return crypto::Sha256Hash(
          write_set_digest,
          commit_evidence_digest.value(),
          claims_digest.value());
      }
    }
    else
    {
      if (claims_digest.empty())
      {
        return crypto::Sha256Hash(write_set_digest);
      }
      else
      {
        return crypto::Sha256Hash(write_set_digest, claims_digest.value());
      }
    }
  }
}