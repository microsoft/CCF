// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash_provider.h"
#include "ds/logger.h"

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

  static ClaimsDigest no_claims()
  {
    return ClaimsDigest();
  }

  static crypto::Sha256Hash entry_leaf(
    const std::vector<uint8_t>& write_set,
    const crypto::Sha256Hash& commit_evidence_digest,
    const ClaimsDigest::Digest& claims_digest)
  {
    crypto::Sha256Hash commit_evidence_digest_empty = {};
    crypto::Sha256Hash write_set_digest({write_set.data(), write_set.size()});
    crypto::Sha256Hash leaf = {};
    if (commit_evidence_digest != commit_evidence_digest_empty)
    {
      leaf = crypto::Sha256Hash(
        write_set_digest, commit_evidence_digest, claims_digest);
    }
    else
    {
      leaf = crypto::Sha256Hash(write_set_digest, claims_digest);
    }

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
    crypto::Sha256Hash commit_evidence_digest_empty = {};
    crypto::Sha256Hash write_set_digest({write_set.data(), write_set.size()});
    crypto::Sha256Hash leaf = {};
    if (commit_evidence_digest != commit_evidence_digest_empty)
    {
      leaf = crypto::Sha256Hash(write_set_digest, commit_evidence_digest);
    }
    else
    {
      leaf = write_set_digest;
    }

    LOG_TRACE_FMT(
      "entry_leaf ws: {} + ce: {} = {}",
      write_set_digest,
      commit_evidence_digest,
      leaf);
    return leaf;
  }
}