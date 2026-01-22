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
  public:
    virtual ~Receipt() = default;

    // Signature over the root digest, signed by the identity described in cert
    std::vector<uint8_t> signature;
    virtual ccf::crypto::Sha256Hash calculate_root() = 0;

    ccf::NodeId node_id;
    ccf::crypto::Pem cert;

    std::vector<ccf::crypto::Pem> service_endorsements;

    [[nodiscard]] virtual bool is_signature_transaction() const = 0;
  };

  // Most transactions produce a receipt constructed from a combination of 3
  // digests. Note that transactions emitted by old code versions may not
  // include a claims_digest or a commit_evidence_digest, but from 2.0 onwards
  // every transaction will contain a (potentially default-zero'd) claims digest
  // and a commit evidence digest.
  class ProofReceipt : public Receipt
  {
  public:
    struct Components
    {
      ccf::crypto::Sha256Hash write_set_digest;
      std::string commit_evidence;
      ccf::ClaimsDigest claims_digest;
    };
    Components leaf_components;

    struct ProofStep
    {
      enum class Direction : uint8_t
      {
        Left,
        Right
      };
      Direction direction = Direction::Left;

      ccf::crypto::Sha256Hash hash;

      bool operator==(const ProofStep& other) const
      {
        return direction == other.direction && hash == other.hash;
      }
    };
    using Proof = std::vector<ProofStep>;

    // A merkle-tree path from the leaf digest to the signed root
    Proof proof;

    ccf::crypto::Sha256Hash calculate_root() override
    {
      auto current = get_leaf_digest();

      for (const auto& element : proof)
      {
        if (element.direction == ProofStep::Direction::Left)
        {
          current = ccf::crypto::Sha256Hash(element.hash, current);
        }
        else
        {
          current = ccf::crypto::Sha256Hash(current, element.hash);
        }
      }

      return current;
    }

    [[nodiscard]] ccf::crypto::Sha256Hash get_leaf_digest() const
    {
      ccf::crypto::Sha256Hash ce_dgst(leaf_components.commit_evidence);
      if (!leaf_components.claims_digest.empty())
      {
        return {
          leaf_components.write_set_digest,
          ce_dgst,
          leaf_components.claims_digest.value()};
      }
      return {leaf_components.write_set_digest, ce_dgst};
    }

    [[nodiscard]] bool is_signature_transaction() const override
    {
      return false;
    }
  };

  // Signature transactions are special, as they contain no proof. They contain
  // a single root, which is directly signed.
  class SignatureReceipt : public Receipt
  {
  public:
    ccf::crypto::Sha256Hash signed_root;

    ccf::crypto::Sha256Hash calculate_root() override
    {
      return signed_root;
    };

    [[nodiscard]] bool is_signature_transaction() const override
    {
      return true;
    }
  };

  using ReceiptPtr = std::shared_ptr<Receipt>;

  // This is an opaque, incomplete type, but can be summarised to a JSON object
  // by describe_receipt_v1, or a ccf::ReceiptPtr by describe_receipt_v2
  struct TxReceiptImpl;
  using TxReceiptImplPtr = std::shared_ptr<TxReceiptImpl>;
  nlohmann::json describe_receipt_v1(const TxReceiptImpl& receipt);
  ReceiptPtr describe_receipt_v2(const TxReceiptImpl& in);

  // NOLINTNEXTLINE(performance-enum-size)
  enum MerkleProofLabel : int64_t
  {
    // Values set in
    // https://github.com/ietf-scitt/draft-birkholz-cose-cometre-ccf-profile
    MERKLE_PROOF_LEAF_LABEL = 1,
    MERKLE_PROOF_PATH_LABEL = 2
  };
  // NOLINTNEXTLINE(performance-enum-size)
  enum MerkleProofPathBranch : int64_t
  {
    // Values set in
    // https://github.com/ietf-scitt/draft-birkholz-cose-cometre-ccf-profile
    LEFT = 0,
    RIGHT = 1
  };
  std::optional<std::vector<uint8_t>> describe_merkle_proof_v1(
    const TxReceiptImpl& receipt);

  using SerialisedCoseEndorsement = std::vector<uint8_t>;
  using SerialisedCoseSignature = std::vector<uint8_t>;
  using SerialisedCoseEndorsements = std::vector<SerialisedCoseEndorsement>;
  std::optional<SerialisedCoseEndorsements> describe_cose_endorsements_v1(
    const TxReceiptImpl& receipt);
  std::optional<SerialisedCoseSignature> describe_cose_signature_v1(
    const TxReceiptImpl& receipt);

  // Manual JSON serializers are specified for these types as they are not
  // trivial POD structs

  void to_json(nlohmann::json& j, const ProofReceipt::Components& components);
  void from_json(const nlohmann::json& j, ProofReceipt::Components& components);
  std::string schema_name(
    [[maybe_unused]] const ProofReceipt::Components* components);
  void fill_json_schema(
    nlohmann::json& schema,
    [[maybe_unused]] const ProofReceipt::Components* components);

  void to_json(nlohmann::json& j, const ProofReceipt::ProofStep& step);
  void from_json(const nlohmann::json& j, ProofReceipt::ProofStep& step);
  std::string schema_name([[maybe_unused]] const ProofReceipt::ProofStep* step);
  void fill_json_schema(
    nlohmann::json& schema,
    [[maybe_unused]] const ProofReceipt::ProofStep* step);

  void to_json(nlohmann::json& j, const ReceiptPtr& receipt);
  void from_json(const nlohmann::json& j, ReceiptPtr& receipt);
  std::string schema_name([[maybe_unused]] const ReceiptPtr* receipt);
  void fill_json_schema(
    nlohmann::json& schema, [[maybe_unused]] const ReceiptPtr* receipt);

  template <typename T>
  void add_schema_components(
    T& helper, nlohmann::json& schema, const ProofReceipt::Components* comp)
  {
    helper.template add_schema_component<
      decltype(ProofReceipt::Components::write_set_digest)>();
    helper.template add_schema_component<
      decltype(ProofReceipt::Components::claims_digest)>();

    fill_json_schema(schema, comp);
  }

  template <typename T>
  void add_schema_components(
    T& helper, nlohmann::json& schema, const ProofReceipt::ProofStep* ps)
  {
    helper
      .template add_schema_component<decltype(ProofReceipt::ProofStep::hash)>();

    fill_json_schema(schema, ps);
  }

  template <typename T>
  void add_schema_components(
    T& helper, nlohmann::json& schema, const ReceiptPtr* r)
  {
    helper.template add_schema_component<decltype(Receipt::cert)>();
    helper.template add_schema_component<decltype(Receipt::node_id)>();
    helper
      .template add_schema_component<decltype(Receipt::service_endorsements)>();
    helper.template add_schema_component<decltype(Receipt::signature)>();

    helper.template add_schema_component<decltype(ProofReceipt::proof)>();
    helper
      .template add_schema_component<decltype(ProofReceipt::leaf_components)>();
    helper
      .template add_schema_component<decltype(SignatureReceipt::signed_root)>();

    fill_json_schema(schema, r);
  }
}
