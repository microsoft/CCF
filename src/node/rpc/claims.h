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
    const ClaimsDigest::Digest& claims_digest,
    const crypto::Sha256Hash& commit_evidence_digest)
  {
    crypto::Sha256Hash write_set_digest({write_set.data(), write_set.size()});
    LOG_TRACE_FMT(
      "entry_leaf ws: {} + cd: {} + ce: {} = {}",
      write_set_digest,
      claims_digest,
      commit_evidence_digest,
      crypto::Sha256Hash(write_set_digest, claims_digest, commit_evidence_digest));
    return crypto::Sha256Hash(write_set_digest, claims_digest, commit_evidence_digest);
  }

  static crypto::Sha256Hash entry_leaf(
    const std::vector<uint8_t>& write_set,
    const crypto::Sha256Hash& commit_evidence_digest)
  {
    crypto::Sha256Hash write_set_digest({write_set.data(), write_set.size()});
    LOG_TRACE_FMT(
      "entry_leaf ws: {} + ce: {} = {}",
      write_set_digest,
      commit_evidence_digest,
      crypto::Sha256Hash(write_set_digest, commit_evidence_digest));
    return crypto::Sha256Hash(write_set_digest, commit_evidence_digest);
  }  
}