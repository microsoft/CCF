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
    std::vector<uint8_t> signature = {};
    virtual ccf::crypto::Sha256Hash calculate_root() = 0;

    ccf::NodeId node_id = {};
    ccf::crypto::Pem cert = {};

    std::vector<ccf::crypto::Pem> service_endorsements = {};

    virtual bool is_signature_transaction() const = 0;
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
      enum
      {
        Left,
        Right
      } direction;

      ccf::crypto::Sha256Hash hash = {};

      bool operator==(const ProofStep& other) const
      {
        return direction == other.direction && hash == other.hash;
      }
    };
    using Proof = std::vector<ProofStep>;

    // A merkle-tree path from the leaf digest to the signed root
    Proof proof = {};

    ccf::crypto::Sha256Hash calculate_root() override
    {
      auto current = get_leaf_digest();

      for (const auto& element : proof)
      {
        if (element.direction == ProofStep::Left)
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

    ccf::crypto::Sha256Hash get_leaf_digest()
    {
      ccf::crypto::Sha256Hash ce_dgst(leaf_components.commit_evidence);
      if (!leaf_components.claims_digest.empty())
      {
        return ccf::crypto::Sha256Hash(
          leaf_components.write_set_digest,
          ce_dgst,
          leaf_components.claims_digest.value());
      }
      else
      {
        return ccf::crypto::Sha256Hash(
          leaf_components.write_set_digest, ce_dgst);
      }
    }

    bool is_signature_transaction() const override
    {
      return false;
    }
  };

  // Signature transactions are special, as they contain no proof. They contain
  // a single root, which is directly signed.
  class SignatureReceipt : public Receipt
  {
  public:
    ccf::crypto::Sha256Hash signed_root = {};

    ccf::crypto::Sha256Hash calculate_root() override
    {
      return signed_root;
    };

    bool is_signature_transaction() const override
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
  ReceiptPtr describe_receipt_v2(const TxReceiptImpl& receipt);

  enum MerkleProofLabel : int64_t
  {
    // Values set in
    // https://github.com/ietf-scitt/draft-birkholz-cose-cometre-ccf-profile
    MERKLE_PROOF_LEAF_LABEL = 1,
    MERKLE_PROOF_PATH_LABEL = 2
  };
  std::optional<std::vector<uint8_t>> describe_merkle_proof_v1(
    const TxReceiptImpl& in);

  using SerialisedCoseEndorsement = std::vector<uint8_t>;
  using SerialisedCoseSignature = std::vector<uint8_t>;
  using SerialisedCoseEndorsements = std::vector<SerialisedCoseEndorsement>;
  std::optional<SerialisedCoseEndorsements> describe_cose_endorsements_v1(
    const TxReceiptImpl& in);
  std::optional<SerialisedCoseSignature> describe_cose_signature_v1(
    const TxReceiptImpl& receipt);

  // Manual JSON serializers are specified for these types as they are not
  // trivial POD structs

  void to_json(nlohmann::json& j, const ProofReceipt::Components& components);
  void from_json(const nlohmann::json& j, ProofReceipt::Components& components);
  std::string schema_name(const ProofReceipt::Components*);
  void fill_json_schema(
    nlohmann::json& schema, const ProofReceipt::Components*);

  void to_json(nlohmann::json& j, const ProofReceipt::ProofStep& step);
  void from_json(const nlohmann::json& j, ProofReceipt::ProofStep& step);
  std::string schema_name(const ProofReceipt::ProofStep*);
  void fill_json_schema(nlohmann::json& schema, const ProofReceipt::ProofStep*);

  void to_json(nlohmann::json& j, const ReceiptPtr& receipt);
  void from_json(const nlohmann::json& j, ReceiptPtr& receipt);
  std::string schema_name(const ReceiptPtr*);
  void fill_json_schema(nlohmann::json& schema, const ReceiptPtr*);

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
