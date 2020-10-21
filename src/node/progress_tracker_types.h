// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "backup_signatures.h"
#include "consensus/aft/revealed_nonces.h"
#include "node_signature.h"
#include "tls/hash.h"
#include "tls/tls.h"
#include "tls/verifier.h"

namespace ccf
{
  struct CertKey
  {
    CertKey(kv::TxID tx_id_) : tx_id(tx_id_) {}

    kv::TxID tx_id;

    bool operator<(const CertKey& rhs) const
    {
      if (tx_id.version == rhs.tx_id.version)
      {
        return tx_id.term < rhs.tx_id.term;
      }
      return tx_id.version < rhs.tx_id.version;
    }
  };

  struct BftNodeSignature : public ccf::NodeSignature
  {
    bool is_primary;
    Nonce nonce;

    BftNodeSignature(
      const std::vector<uint8_t>& sig_, NodeId node_, Nonce hashed_nonce_) :
      NodeSignature(sig_, node_, hashed_nonce_),
      is_primary(false)
    {}
  };

  struct CommitCert
  {
    CommitCert(crypto::Sha256Hash& root_, Nonce my_nonce_) :
      root(root_),
      my_nonce(my_nonce_),
      have_primary_signature(true)
    {}

    CommitCert() = default;

    crypto::Sha256Hash root;
    std::map<kv::NodeId, BftNodeSignature> sigs;
    std::set<kv::NodeId> sig_acks;
    std::set<kv::NodeId> nonce_set;
    std::map<kv::NodeId, Nonce> unmatched_nonces;
    Nonce my_nonce;
    bool have_primary_signature = false;
    bool ack_sent = false;
    bool reply_and_nonce_sent = false;
    bool nonces_committed_to_ledger = false;
  };

  class ProgressTrackerStore
  {
  public:
    virtual ~ProgressTrackerStore() = default;
    virtual void write_backup_signatures(ccf::BackupSignatures& sig_value) = 0;
    virtual std::optional<ccf::BackupSignatures> get_backup_signatures() = 0;
    virtual void write_nonces(aft::RevealedNonces& nonces) = 0;
    virtual std::optional<aft::RevealedNonces> get_nonces() = 0;
    virtual bool verify_signature(
      kv::NodeId node_id,
      crypto::Sha256Hash& root,
      uint32_t sig_size,
      uint8_t* sig) = 0;
  };

  class ProgressTrackerStoreAdapter : public ProgressTrackerStore
  {
  public:
    ProgressTrackerStoreAdapter(
      kv::AbstractStore& store_,
      ccf::Nodes& nodes_,
      ccf::BackupSignaturesMap& backup_signatures_,
      aft::RevealedNoncesMap& revealed_nonces_) :
      store(store_),
      nodes(nodes_),
      backup_signatures(backup_signatures_),
      revealed_nonces(revealed_nonces_)
    {}

    void write_backup_signatures(ccf::BackupSignatures& sig_value) override
    {
      kv::Tx tx(&store);
      auto backup_sig_view = tx.get_view(backup_signatures);

      backup_sig_view->put(0, sig_value);
      auto r = tx.commit();
      LOG_TRACE_FMT("Adding signatures to ledger, result:{}", r);
      CCF_ASSERT_FMT(
        r == kv::CommitSuccess::OK,
        "Commiting backup signatures failed r:{}",
        r);
    }

    std::optional<ccf::BackupSignatures> get_backup_signatures() override
    {
      kv::Tx tx(&store);
      auto sigs_tv = tx.get_view(backup_signatures);
      auto sigs = sigs_tv->get(0);
      if (!sigs.has_value())
      {
        LOG_FAIL_FMT("No signatures found in signatures map");
        throw ccf::ccf_logic_error("No signatures found in signatures map");
      }
      return sigs;
    }

    void write_nonces(aft::RevealedNonces& nonces) override
    {
      kv::Tx tx(&store);
      auto nonces_tv = tx.get_view(revealed_nonces);

      nonces_tv->put(0, nonces);
      auto r = tx.commit();
      if (r != kv::CommitSuccess::OK)
      {
        LOG_FAIL_FMT(
          "Failed to write nonces, view:{}, seqno:{}",
          nonces.tx_id.term,
          nonces.tx_id.version);
        throw ccf::ccf_logic_error(fmt::format(
          "Failed to write nonces, view:{}, seqno:{}",
          nonces.tx_id.term,
          nonces.tx_id.version));
      }
    }

    std::optional<aft::RevealedNonces> get_nonces() override
    {
      kv::Tx tx(&store);
      auto nonces_tv = tx.get_view(revealed_nonces);
      auto nonces = nonces_tv->get(0);
      if (!nonces.has_value())
      {
        LOG_FAIL_FMT("No signatures found in signatures map");
        throw ccf::ccf_logic_error("No signatures found in signatures map");
      }
      return nonces;
    }

    bool verify_signature(
      kv::NodeId node_id,
      crypto::Sha256Hash& root,
      uint32_t sig_size,
      uint8_t* sig) override
    {
      kv::Tx tx(&store);
      auto ni_tv = tx.get_view(nodes);

      auto ni = ni_tv->get(node_id);
      if (!ni.has_value())
      {
        LOG_FAIL_FMT(
          "No node info, and therefore no cert for node {}", node_id);
        return false;
      }
      tls::VerifierPtr from_cert = tls::make_verifier(ni.value().cert);
      return from_cert->verify_hash(
        root.h.data(), root.h.size(), sig, sig_size);
    }

  private:
    kv::AbstractStore& store;
    ccf::Nodes& nodes;
    ccf::BackupSignaturesMap& backup_signatures;
    aft::RevealedNoncesMap& revealed_nonces;
  };
}
