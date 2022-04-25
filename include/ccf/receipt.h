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

      bool operator==(const ProofStep& other) const
      {
        return direction == other.direction && hash == other.hash;
      }
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
    crypto::Sha256Hash leaf = {};

    crypto::Sha256Hash get_leaf_digest() override
    {
      return leaf;
    };
  };

  using ReceiptPtr = std::shared_ptr<Receipt>;

  // This is an opaque, incomplete type, but can be summarised to a readable
  // (and JSON-serialisable) form by ccf::describe_receipt
  struct TxReceiptImpl;
  using TxReceiptImplPtr = std::shared_ptr<TxReceiptImpl>;
  ReceiptPtr describe_receipt(const TxReceiptImpl& receipt);

  // Manual JSON serializers are specified for these types as they are not
  // trivial POD structs

  void to_json(nlohmann::json& j, const LeafExpandedReceipt::Components& step);
  void from_json(
    const nlohmann::json& j, LeafExpandedReceipt::Components& step);
  std::string schema_name(const LeafExpandedReceipt::Components*);
  void fill_json_schema(
    nlohmann::json& schema, const LeafExpandedReceipt::Components*);

  void to_json(nlohmann::json& j, const Receipt::ProofStep& step);
  void from_json(const nlohmann::json& j, Receipt::ProofStep& step);
  std::string schema_name(const Receipt::ProofStep*);
  void fill_json_schema(nlohmann::json& schema, const Receipt::ProofStep*);

  void to_json(nlohmann::json& j, const ReceiptPtr& receipt);
  void from_json(const nlohmann::json& j, ReceiptPtr& receipt);
  std::string schema_name(const ReceiptPtr*);
  void fill_json_schema(nlohmann::json& schema, const ReceiptPtr*);

  // TODO: Ensure dependency schemas are correctly added to components
  template <typename T>
  void add_schema_components(
    T& helper,
    nlohmann::json& schema,
    const LeafExpandedReceipt::Components* comp)
  {
    helper.template add_schema_component<decltype(
      LeafExpandedReceipt::Components::write_set_digest)>();
    helper.template add_schema_component<decltype(
      LeafExpandedReceipt::Components::claims_digest)>();

    fill_json_schema(schema, comp);
  }

  template <typename T>
  void add_schema_components(
    T& helper, nlohmann::json& schema, const Receipt::ProofStep* ps)
  {
    helper.template add_schema_component<decltype(Receipt::ProofStep::hash)>();

    fill_json_schema(schema, ps);
  }

  template <typename T>
  void add_schema_components(
    T& helper, nlohmann::json& schema, const ReceiptPtr* r)
  {
    helper.template add_schema_component<decltype(Receipt::cert)>();
    helper.template add_schema_component<decltype(Receipt::node_id)>();
    helper.template add_schema_component<decltype(Receipt::proof)>();
    helper
      .template add_schema_component<decltype(Receipt::service_endorsements)>();
    helper.template add_schema_component<decltype(Receipt::signature)>();

    helper.template add_schema_component<decltype(
      LeafExpandedReceipt::leaf_components)>();
    helper.template add_schema_component<decltype(LeafDigestReceipt::leaf)>();

    fill_json_schema(schema, r);
  }
}
