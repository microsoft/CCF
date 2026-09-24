// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/node/cose_signatures_config.h"
#include "crypto/openssl/ec_key_pair.h"
#include "ds/internal_logger.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "service/tables/signatures.h"

#include <memory>
#include <optional>
#include <tuple>
#include <vector>

namespace ccf
{
  // Test-only TxHistory which does not build a Merkle tree or sign anything,
  // but still writes placeholder entries to the signature tables when a
  // signature is emitted, so that transactions depending on those tables can
  // be exercised without a real history.
  class NullTxHistoryPendingTx : public ccf::kv::PendingTx
  {
    ccf::TxID txid;
    ccf::kv::Store& store;
    NodeId id;

  public:
    NullTxHistoryPendingTx(
      ccf::TxID txid_, ccf::kv::Store& store_, NodeId id_) :
      txid(txid_),
      store(store_),
      id(std::move(id_))
    {}

    ccf::kv::PendingTxInfo call() override
    {
      auto sig = store.create_reserved_tx(txid);
      auto* signatures =
        sig.template wo<ccf::Signatures>(ccf::Tables::SIGNATURES);
      auto* cose_signatures =
        sig.template wo<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);

      auto* serialised_tree = sig.template wo<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      PrimarySignature sig_value(id, txid.seqno);
      signatures->put(sig_value);
      cose_signatures->put(ccf::IdentityType::CLASSICAL, ccf::CoseSignature{});
      serialised_tree->put({});
      return sig.commit_reserved();
    }
  };

  class NullTxHistory : public ccf::kv::TxHistory
  {
    ccf::kv::Store& store;
    NodeId id;

  protected:
    ccf::kv::Version version = 0;
    ccf::kv::Term term_of_last_version = 0;
    ccf::kv::Term term_of_next_version = 0;

  public:
    NullTxHistory(
      ccf::kv::Store& store_, NodeId id_, ccf::crypto::ECKeyPair& /*unused*/) :
      store(store_),
      id(std::move(id_))
    {}

    void append(const std::vector<uint8_t>& /*data*/) override
    {
      version++;
    }

    void append_entry(
      const ccf::crypto::Sha256Hash& /*digest*/,
      std::optional<ccf::kv::Term> /*term_of_next_version_*/ =
        std::nullopt) override
    {
      version++;
    }

    bool verify_root_signatures(ccf::kv::Version /*v*/) override
    {
      return true;
    }

    void set_term(ccf::kv::Term t) override
    {
      term_of_last_version = t;
      term_of_next_version = t;
    }

    void rollback(const ccf::TxID& tx_id, ccf::kv::Term commit_term_) override
    {
      version = tx_id.seqno;
      term_of_last_version = tx_id.view;
      term_of_next_version = commit_term_;
    }

    void compact(ccf::kv::Version /*v*/) override {}

    bool init_from_snapshot(
      const std::vector<uint8_t>& /*hash_at_snapshot*/) override
    {
      return true;
    }

    std::vector<uint8_t> get_raw_leaf(uint64_t /*index*/) override
    {
      return {};
    }

    void emit_signature() override
    {
      auto txid = store.next_txid();
      LOG_DEBUG_FMT("Issuing signature at {}.{}", txid.view, txid.seqno);
      store.commit(
        txid, std::make_unique<NullTxHistoryPendingTx>(txid, store, id), true);
    }

    void try_emit_signature() override {}

    void start_signature_emit_timer() override {}

    void set_service_signing_identity(
      std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> service_kp_,
      const ccf::COSESignaturesConfig& /*cose_signatures*/) override
    {
      std::ignore = service_kp_;
    }

    const ccf::COSESignaturesConfig& get_cose_signatures_config() override
    {
      throw std::logic_error("Unimplemented");
    }

    ccf::crypto::Sha256Hash get_replicated_state_root() override
    {
      return ccf::crypto::Sha256Hash(std::to_string(version));
    }

    std::tuple<ccf::TxID, ccf::crypto::Sha256Hash, ccf::kv::Term>
    get_replicated_state_txid_and_root() override
    {
      return {
        {term_of_last_version, version},
        ccf::crypto::Sha256Hash(std::to_string(version)),
        term_of_next_version};
    }

    std::vector<uint8_t> get_proof(ccf::kv::Version /*v*/) override
    {
      return {};
    }

    bool verify_proof(const std::vector<uint8_t>& /*proof*/) override
    {
      return true;
    }

    std::vector<uint8_t> serialise_tree(size_t /*to*/) override
    {
      return {};
    }

    void set_endorsed_certificate(const ccf::crypto::Pem& /*cert*/) override {}
  };
}
