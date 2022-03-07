// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "ccf/service/map.h"

#include <string>
#include <vector>

namespace aft
{
  using Nonce = crypto::Sha256Hash;
  struct RevealedNonce
  {
    ccf::NodeId node_id;
    Nonce nonce;

    RevealedNonce(const ccf::NodeId& node_id_, Nonce nonce_) :
      node_id(node_id_),
      nonce(nonce_)
    {}

    RevealedNonce() = default;
  };
  DECLARE_JSON_TYPE(RevealedNonce);
  DECLARE_JSON_REQUIRED_FIELDS(RevealedNonce, node_id, nonce)

  struct RevealedNonces
  {
    ccf::TxID tx_id;
    std::vector<RevealedNonce> nonces;

    RevealedNonces() = default;

    RevealedNonces(ccf::TxID tx_id_) : tx_id(tx_id_) {}
  };
  DECLARE_JSON_TYPE(RevealedNonces);
  DECLARE_JSON_REQUIRED_FIELDS(RevealedNonces, tx_id, nonces)

  using RevealedNoncesMap = ccf::ServiceValue<RevealedNonces>;
  namespace Tables
  {
    static constexpr auto NONCES = "public:ccf.internal.consensus.nonces";
  }
}