// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/receipt.h"
#include "node/history.h"

namespace ccf
{
  struct TxReceipt
  {
    std::vector<uint8_t> signature = {};
    HistoryTree::Hash root = {};
    std::shared_ptr<ccf::HistoryTree::Path> path = {};
    ccf::NodeId node_id = {};
    std::optional<crypto::Pem> cert = std::nullopt;
    std::optional<crypto::Sha256Hash> write_set_digest = std::nullopt;
    std::optional<std::string> commit_evidence = std::nullopt;
    ccf::ClaimsDigest claims_digest = {};
    std::optional<std::vector<crypto::Pem>> service_endorsements = std::nullopt;

    TxReceipt(
      const std::vector<uint8_t>& s_,
      const HistoryTree::Hash& r_,
      std::shared_ptr<ccf::HistoryTree::Path> p_,
      const NodeId& n_,
      const std::optional<crypto::Pem>& c_,
      const std::optional<crypto::Sha256Hash>& write_set_digest_ = std::nullopt,
      const std::optional<std::string>& commit_evidence_ = std::nullopt,
      const ccf::ClaimsDigest& claims_digest_ = ccf::no_claims(),
      const std::optional<std::vector<crypto::Pem>>& service_endorsements_ =
        std::nullopt) :
      signature(s_),
      root(r_),
      path(p_),
      node_id(n_),
      cert(c_),
      write_set_digest(write_set_digest_),
      commit_evidence(commit_evidence_),
      claims_digest(claims_digest_),
      service_endorsements(service_endorsements_)
    {}
  };

  using TxReceiptPtr = std::shared_ptr<TxReceipt>;
}
