// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/claims_digest.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/sha256_hash.h"
#include "ccf/ds/json.h"
#include "ccf/ds/openapi.h"
#include "ccf/entity_id.h"

#include <optional>
#include <string>

namespace ccf
{
  class Receipt
  {
  private:
    // Lazily constructed
    std::optional<crypto::Sha256Hash> root = std::nullopt;

  public:
    virtual ~Receipt() = default;

    std::vector<uint8_t> signature = {};
    crypto::Sha256Hash get_root()
    {
      if (!root.has_value())
      {
        auto current = get_leaf_digest();

        for (const auto& element : proof)
        {
          if (element.direction == ProofStep::Left)
          {
            current = crypto::Sha256Hash(element.hash, current);
          }
          else
          {
            current = crypto::Sha256Hash(current, element.hash);
          }
        }

        root = current;
      }

      return root.value();
    }

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
    Proof proof = {};

    virtual crypto::Sha256Hash get_leaf_digest() = 0;

    ccf::NodeId node_id = {};
    crypto::Pem cert = {};

    std::vector<crypto::Pem> service_endorsements = {};
  };

  class LeafExpandedReceipt : public Receipt
  {
  public:
    struct Components
    {
      crypto::Sha256Hash write_set_digest;
      std::string commit_evidence;
      // https://github.com/microsoft/CCF/issues/3606
      std::optional<ccf::ClaimsDigest> claims_digest;
    };

    Components leaf_components;

    crypto::Sha256Hash get_leaf_digest() override
    {
      crypto::Sha256Hash ce_dgst(leaf_components.commit_evidence);
      return crypto::Sha256Hash(
        leaf_components.write_set_digest,
        ce_dgst,
        leaf_components.claims_digest
          ->value()); // TODO: What about when this is empty?
    }
  };

  class LeafDigestReceipt : public Receipt
  {
  public:
    crypto::Sha256Hash leaf_digest = {};

    crypto::Sha256Hash get_leaf_digest() override
    {
      return leaf_digest;
    };
  };

  using ReceiptPtr = std::shared_ptr<Receipt>;

  // This is an opaque, incomplete type, but can be summarised to a readable
  // (and JSON-serialisable) form by ccf::describe_receipt
  struct TxReceiptImpl;
  using TxReceiptImplPtr = std::shared_ptr<TxReceiptImpl>;
  ReceiptPtr describe_receipt(const TxReceiptImpl& receipt);

  // Manual JSON serializers are specified for this variant type
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
      auto schema = nlohmann::json::object();
      schema["required"] = nlohmann::json::array();
      schema["required"].push_back(name);
      schema["properties"] = nlohmann::json::object();
      schema["properties"][name] = ds::openapi::components_ref_object(
        ds::json::schema_name<crypto::Sha256Hash>());
      return schema;
    };

    schema["type"] = "object";
    schema["oneOf"] = nlohmann::json::array();
    schema["oneOf"].push_back(possible_hash("left"));
    schema["oneOf"].push_back(possible_hash("right"));
  }

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(LeafExpandedReceipt::Components);
  DECLARE_JSON_REQUIRED_FIELDS(
    LeafExpandedReceipt::Components, write_set_digest, commit_evidence);
  DECLARE_JSON_OPTIONAL_FIELDS(LeafExpandedReceipt::Components, claims_digest);

  inline void to_json(nlohmann::json& j, const ReceiptPtr& receipt) {}

  inline void from_json(const nlohmann::json& j, ReceiptPtr& receipt) {}

  inline std::string schema_name(const ReceiptPtr*)
  {
    return "Receipt";
  }

  inline void fill_json_schema(nlohmann::json& schema, const ReceiptPtr*) {}

  // DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Receipt);
  // DECLARE_JSON_REQUIRED_FIELDS(Receipt, signature, proof, node_id, cert);
  // DECLARE_JSON_OPTIONAL_FIELDS(Receipt, service_endorsements);
}
