// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/network_identity_interface.h"
#include "ccf/receipt.h"
#include "node/history.h"

namespace ccf
{
  // Representation of receipt used by internal framework code. Mirrored in
  // public interface by ccf::Receipt
  struct TxReceiptImpl
  {
    std::vector<uint8_t> signature;
    std::optional<std::vector<uint8_t>> cose_signature = std::nullopt;
    HistoryTree::Hash root;
    std::shared_ptr<ccf::HistoryTree::Path> path;
    ccf::NodeId node_id;
    std::optional<ccf::crypto::Pem> node_cert = std::nullopt;
    std::optional<ccf::crypto::Sha256Hash> write_set_digest = std::nullopt;
    std::optional<std::string> commit_evidence = std::nullopt;
    ccf::ClaimsDigest claims_digest;
    std::optional<std::vector<ccf::crypto::Pem>> service_endorsements =
      std::nullopt;
    std::optional<CoseEndorsementsChain> cose_endorsements = std::nullopt;

    TxReceiptImpl(
      const std::vector<uint8_t>& signature_,
      const std::optional<std::vector<uint8_t>>& cose_signature,
      const HistoryTree::Hash& root_,
      std::shared_ptr<ccf::HistoryTree::Path> path_,
      NodeId node_id_,
      const std::optional<ccf::crypto::Pem>& node_cert_,
      const std::optional<ccf::crypto::Sha256Hash>& write_set_digest_ =
        std::nullopt,
      // Optional to support historical transactions, where it may be absent
      const std::optional<std::string>& commit_evidence_ = std::nullopt,
      // May not be set on historical transactions
      ccf::ClaimsDigest claims_digest_ = ccf::no_claims(),
      const std::optional<std::vector<ccf::crypto::Pem>>&
        service_endorsements_ = std::nullopt,
      const std::optional<CoseEndorsementsChain>& cose_endorsements_ =
        std::nullopt) :
      signature(signature_),
      cose_signature(cose_signature),
      root(root_),
      path(std::move(path_)),
      node_id(std::move(node_id_)),
      node_cert(node_cert_),
      write_set_digest(write_set_digest_),
      commit_evidence(commit_evidence_),
      claims_digest(std::move(claims_digest_)),
      service_endorsements(service_endorsements_),
      cose_endorsements(cose_endorsements_)
    {}
  };

  using TxReceiptImplPtr = std::shared_ptr<TxReceiptImpl>;
}
