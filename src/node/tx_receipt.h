// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/receipt.h"
#include "ccf/crypto/base64.h"
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

    TxReceipt(
      const std::vector<uint8_t>& s_,
      const HistoryTree::Hash& r_,
      std::shared_ptr<ccf::HistoryTree::Path> p_,
      const NodeId& n_,
      const std::optional<crypto::Pem>& c_,
      const std::optional<crypto::Sha256Hash>& write_set_digest_ = std::nullopt,
      const std::optional<std::string>& commit_evidence_ = std::nullopt,
      const ccf::ClaimsDigest& claims_digest_ = ccf::no_claims()) :
      signature(s_),
      root(r_),
      path(p_),
      node_id(n_),
      cert(c_),
      write_set_digest(write_set_digest_),
      commit_evidence(commit_evidence_),
      claims_digest(claims_digest_)
    {}

    void describe(ccf::Receipt& r, bool include_root = false) const
    {
      r.signature = crypto::b64_from_raw(signature);
      if (include_root)
      {
        r.root = root.to_string();
      }
      if (path != nullptr)
      {
        for (const auto& node : *path)
        {
          ccf::Receipt::Element n;
          if (node.direction == ccf::HistoryTree::Path::Direction::PATH_LEFT)
          {
            n.left = node.hash.to_string();
          }
          else
          {
            n.right = node.hash.to_string();
          }
          r.proof.emplace_back(std::move(n));
        }
      }
      r.node_id = node_id;

      if (cert.has_value())
      {
        r.cert = cert->str();
      }

      if (path == nullptr)
      {
        // Signature transaction
        r.leaf = root.to_string();
      }
      else if (!commit_evidence.has_value())
      {
        r.leaf = write_set_digest->hex_str();
      }
      else
      {
        std::optional<std::string> write_set_digest_str = std::nullopt;
        if (write_set_digest.has_value())
          write_set_digest_str = write_set_digest->hex_str();
        std::optional<std::string> claims_digest_str = std::nullopt;
        if (!claims_digest.empty())
          claims_digest_str = claims_digest.value().hex_str();
        r.leaf_components = Receipt::LeafComponents{
          write_set_digest_str, commit_evidence, claims_digest_str};
      }
    }
  };

  using TxReceiptPtr = std::shared_ptr<TxReceipt>;
}
