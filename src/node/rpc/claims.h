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
    const crypto::Sha256Hash& commit_evidence_digest,
    const ClaimsDigest::Digest& claims_digest)
  {
    crypto::Sha256Hash write_set_digest({write_set.data(), write_set.size()});
    auto leaf = crypto::Sha256Hash(
      write_set_digest, commit_evidence_digest, claims_digest);
    LOG_TRACE_FMT(
      "entry_leaf ws: {} + ce: {} + cd: {} = {}",
      write_set_digest,
      commit_evidence_digest,
      claims_digest,
      leaf);
    return leaf;
  }

  static crypto::Sha256Hash entry_leaf(
    const std::vector<uint8_t>& write_set,
    const crypto::Sha256Hash& commit_evidence_digest)
  {
    crypto::Sha256Hash write_set_digest({write_set.data(), write_set.size()});
    auto leaf = crypto::Sha256Hash(write_set_digest, commit_evidence_digest);
    LOG_TRACE_FMT(
      "entry_leaf ws: {} + ce: {} = {}",
      write_set_digest,
      commit_evidence_digest,
      leaf);
    return leaf;
  }
}