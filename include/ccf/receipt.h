// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/claims_digest.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/sha256_hash.h"
#include "ccf/ds/json.h"
#include "ccf/entity_id.h"

#include <optional>
#include <string>

namespace ccf
{
  class Receipt
  {
  public:
    virtual ~Receipt() = default;

    struct PathStep
    {
      enum
      {
        Left,
        Right
      } direction;

      crypto::Sha256Hash hash = {};
    };

    using Path = std::vector<PathStep>;

    struct LeafComponents
    {
      crypto::Sha256Hash write_set_digest;
      std::string commit_evidence;
      ccf::ClaimsDigest claims_digest;
    };

    std::vector<uint8_t> signature = {};

    crypto::Sha256Hash root = {};
    Path path = {};

    LeafComponents leaf_components = {};
    crypto::Sha256Hash get_leaf_hash()
    {
      // TODO
      return {};  
    }

    ccf::NodeId node_id = {};
    crypto::Pem node_cert = {};
  };

  using ReceiptPtr = std::shared_ptr<Receipt>;

  // TODO: Should this be implemented here, or in .cpp?
  inline void to_json(nlohmann::json& j, const Receipt::PathStep& step) {}
  inline void from_json(const nlohmann::json& j, Receipt::PathStep& step) {}
  inline std::string schema_name(const Receipt::PathStep*)
  {
    return "ReceiptPathStep";
  }
  inline void fill_json_schema(nlohmann::json& schema, const Receipt::PathStep*) {}

  inline void to_json(nlohmann::json& j, const Receipt::LeafComponents& lc) {}
  inline void from_json(const nlohmann::json& j, Receipt::LeafComponents& lc) {}
  inline std::string schema_name(const Receipt::LeafComponents*)
  {
    return "ReceiptLeafComponents";
  }
  inline void fill_json_schema(nlohmann::json& schema, const Receipt::LeafComponents*)
  {}

  inline void to_json(nlohmann::json& j, const Receipt& r) {}
  inline void from_json(const nlohmann::json& j, Receipt& r) {}
  inline std::string schema_name(const Receipt*)
  {
    return "Receipt";
  }
  inline void fill_json_schema(nlohmann::json& schema, const Receipt*) {}
}
