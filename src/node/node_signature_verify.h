// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/verifier.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/tx.h"

namespace ccf
{
  static bool verify_node_signature(
    ccf::kv::ReadOnlyTx& tx,
    const NodeId& node_id,
    const uint8_t* expected_sig,
    size_t expected_sig_size,
    const uint8_t* expected_root,
    size_t expected_root_size)
  {
    ccf::crypto::Pem node_cert;
    auto* node_endorsed_certs = tx.template ro<ccf::NodeEndorsedCertificates>(
      ccf::Tables::NODE_ENDORSED_CERTIFICATES);
    auto node_endorsed_cert = node_endorsed_certs->get(node_id);
    if (!node_endorsed_cert.has_value())
    {
      // No endorsed certificate for node. Its (self-signed) certificate
      // must be stored in the nodes table (1.x ledger only)

      auto* nodes = tx.template ro<ccf::Nodes>(ccf::Tables::NODES);
      auto node = nodes->get(node_id);
      if (!node.has_value())
      {
        LOG_FAIL_FMT(
          "Signature cannot be verified: no certificate found for node {}",
          node_id);
        return false;
      }

      if (!node->cert.has_value())
      {
        LOG_FAIL_FMT(
          "No certificate recorded in nodes table for {} (1.x ledger)",
          node_id);
        return false;
      }

      node_cert = node->cert.value();
    }
    else
    {
      node_cert = node_endorsed_cert.value();
    }

    ccf::crypto::VerifierPtr from_cert = ccf::crypto::make_verifier(node_cert);
    return from_cert->verify_hash(
      expected_root,
      expected_root_size,
      expected_sig,
      expected_sig_size,
      ccf::crypto::MDType::SHA256);
  }

  static bool verify_node_signature(
    ccf::kv::ReadOnlyTx& tx,
    const NodeId& node_id,
    const std::vector<uint8_t>& expected_sig,
    const ccf::crypto::Sha256Hash& expected_root)
  {
    return verify_node_signature(
      tx,
      node_id,
      expected_sig.data(),
      expected_sig.size(),
      expected_root.h.data(),
      expected_root.h.size());
  }
}