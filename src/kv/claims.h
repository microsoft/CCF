// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/claims_digest.h"
#include "ccf/crypto/sha256_hash.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace ccf
{
  inline ClaimsDigest no_claims()
  {
    return {};
  }

  inline ccf::crypto::Sha256Hash entry_leaf(
    const std::vector<uint8_t>& write_set,
    const std::optional<ccf::crypto::Sha256Hash>& commit_evidence_digest,
    const ClaimsDigest& claims_digest)
  {
    ccf::crypto::Sha256Hash write_set_digest(write_set);

    if (commit_evidence_digest.has_value())
    {
      if (claims_digest.empty())
      {
        return {write_set_digest, commit_evidence_digest.value()};
      }
      return {
        write_set_digest,
        commit_evidence_digest.value(),
        claims_digest.value()};
    }

    if (claims_digest.empty())
    {
      return {write_set_digest};
    }
    return {write_set_digest, claims_digest.value()};
  }
}