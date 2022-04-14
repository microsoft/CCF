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

    struct ProofStep
    {
      enum
      {
        Left,
        Right
      } direction;

      crypto::Sha256Hash hash = {};
    };

    using Proof = std::vector<ProofStep>;

    struct LeafComponents
    {
      crypto::Sha256Hash write_set_digest;
      std::string commit_evidence;
      ccf::ClaimsDigest claims_digest;
    };

    std::vector<uint8_t> signature = {};

    crypto::Sha256Hash root = {};
    Proof proof = {};

    LeafComponents leaf_components = {};
    crypto::Sha256Hash get_leaf_hash()
    {
      // TODO
      return {};
    }

    ccf::NodeId node_id = {};
    crypto::Pem cert = {};

    std::vector<crypto::Pem> service_endorsements = {};
  };

  using ReceiptPtr = std::shared_ptr<Receipt>;

  // Manual JSON serializers for this non-trivial type
  inline void to_json(nlohmann::json& j, const Receipt::ProofStep& step)
  {
    j = nlohmann::json::object();
    const auto key =
      step.direction == Receipt::ProofStep::Left ? "left" : "right";
    j[key] = step.hash;
  }

  inline void from_json(const nlohmann::json& j, Receipt::ProofStep& step)
  {
    if (!j.is_object())
    {
      throw JsonParseError(fmt::format(
        "Cannot parse Receipt Step: Expected object, got {}", j.dump()));
    }

    const auto l_it = j.find("left");
    const auto r_it = j.find("right");
    if ((l_it == j.end()) == (r_it == j.end()))
    {
      throw JsonParseError(fmt::format(
        "Cannot parse Receipt Step: Expected either 'left' or 'right' field, "
        "got {}",
        j.dump()));
    }

    if (l_it != j.end())
    {
      step.direction = Receipt::ProofStep::Left;
      step.hash = l_it.value();
    }
    else
    {
      step.direction = Receipt::ProofStep::Right;
      step.hash = r_it.value();
    }
  }

  inline std::string schema_name(const Receipt::ProofStep*)
  {
    return "Receipt__Element";
  }

  inline void fill_json_schema(
    nlohmann::json& schema, const Receipt::ProofStep*)
  {
    schema = nlohmann::json::object();

    auto possible_hash = [](const auto& name) {
      auto hash_schema = nlohmann::json::object();
      hash_schema["type"] = "TODO";
      auto properties = nlohmann::json::object();
      properties[name] = hash_schema;
      auto required = nlohmann::json::array();
      required.push_back(name);
      auto ret = nlohmann::json::object();
      ret["properties"] = properties;
      ret["required"] = required;
      return ret;
    };

    schema["type"] = "object";
    schema["oneOf"] = nlohmann::json::array();
    schema["oneOf"].push_back(possible_hash("left"));
    schema["oneOf"].push_back(possible_hash("right"));
  }

  DECLARE_JSON_TYPE(Receipt::LeafComponents);
  DECLARE_JSON_REQUIRED_FIELDS(
    Receipt::LeafComponents, write_set_digest, commit_evidence, claims_digest);

  DECLARE_JSON_TYPE(Receipt);
  DECLARE_JSON_REQUIRED_FIELDS(
    Receipt,
    signature,
    root,
    proof,
    leaf_components,
    node_id,
    cert,
    service_endorsements);
}
