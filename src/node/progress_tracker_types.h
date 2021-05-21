// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "backup_signatures.h"
#include "blit.h"
#include "consensus/aft/revealed_nonces.h"
#include "crypto/hash.h"
#include "crypto/verifier.h"
#include "kv/committable_tx.h"
#include "node_signature.h"
#include "tls/tls.h"
#include "view_change.h"

namespace ccf
{
  struct BftNodeSignature : public NodeSignature
  {
    bool is_primary;
    Nonce nonce;

    BftNodeSignature(const NodeSignature& ns) :
      NodeSignature(ns),
      is_primary(false)
    {}

    BftNodeSignature(
      const std::vector<uint8_t>& sig_,
      const NodeId& node_,
      Nonce hashed_nonce_) :
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
    std::map<NodeId, BftNodeSignature> sigs;
    std::set<NodeId> sig_acks;
    std::set<NodeId> nonce_set;
    std::map<NodeId, Nonce> unmatched_nonces;
    Nonce my_nonce;
    bool have_primary_signature = false;
    bool ack_sent = false;
    bool reply_and_nonce_sent = false;
    bool nonces_committed_to_ledger = false;
    bool wrote_sig_to_ledger = false;
  };

  class ProgressTrackerStore
  {
  public:
    virtual ~ProgressTrackerStore() = default;
    virtual void write_backup_signatures(const BackupSignatures& sig_value) = 0;
    virtual std::optional<BackupSignatures> get_backup_signatures() = 0;
    virtual std::optional<ViewChangeConfirmation> get_new_view() = 0;
    virtual void write_nonces(aft::RevealedNonces& nonces) = 0;
    virtual std::optional<aft::RevealedNonces> get_nonces() = 0;
    virtual bool verify_signature(
      const NodeId& node_id,
      crypto::Sha256Hash& root,
      uint32_t sig_size,
      uint8_t* sig) = 0;
    virtual void sign_view_change_request(
      ViewChangeRequest& view_change, ccf::View view, ccf::SeqNo seqno) = 0;
    virtual bool verify_view_change_request(
      ViewChangeRequest& view_change,
      const NodeId& from,
      ccf::View view,
      ccf::SeqNo seqno) = 0;
    virtual ccf::SeqNo write_view_change_confirmation(
      ViewChangeConfirmation& new_view) = 0;
    virtual bool verify_view_change_request_confirmation(
      ViewChangeConfirmation& new_view, const NodeId& from) = 0;
  };

  class ProgressTrackerStoreAdapter : public ProgressTrackerStore
  {
  public:
    ProgressTrackerStoreAdapter(
      kv::AbstractStore& store_, crypto::KeyPair& kp_) :
      store(store_),
      kp(kp_),
      nodes(Tables::NODES),
      backup_signatures(Tables::BACKUP_SIGNATURES),
      revealed_nonces(Tables::NONCES),
      new_views(Tables::NEW_VIEWS)
    {}

    void write_backup_signatures(const BackupSignatures& sig_value) override
    {
      kv::CommittableTx tx(&store);
      auto backup_sig_view = tx.rw(backup_signatures);

      backup_sig_view->put(0, sig_value);
      auto r = tx.commit();
      LOG_TRACE_FMT("Adding signatures to ledger, result:{}", r);
      CCF_ASSERT_FMT(
        r == kv::CommitResult::SUCCESS,
        "Commiting backup signatures failed r:{}",
        r);
    }

    std::optional<BackupSignatures> get_backup_signatures() override
    {
      kv::ReadOnlyTx tx(&store);
      auto sigs_tv = tx.ro(backup_signatures);
      auto sigs = sigs_tv->get(0);
      if (!sigs.has_value())
      {
        LOG_FAIL_FMT("No signatures found in signatures map");
        throw ccf_logic_error("No signatures found in signatures map");
      }
      return sigs;
    }

    std::optional<ViewChangeConfirmation> get_new_view() override
    {
      kv::ReadOnlyTx tx(&store);
      auto new_views_tv = tx.ro(new_views);
      auto new_view = new_views_tv->get(0);
      if (!new_view.has_value())
      {
        LOG_FAIL_FMT("No new_view found in new_view map");
        throw ccf_logic_error("No new_view found in new_view map");
      }
      return new_view;
    }

    void write_nonces(aft::RevealedNonces& nonces) override
    {
      kv::CommittableTx tx(&store);
      auto nonces_tv = tx.rw(revealed_nonces);

      nonces_tv->put(0, nonces);
      auto r = tx.commit();
      if (r != kv::CommitResult::SUCCESS)
      {
        LOG_FAIL_FMT(
          "Failed to write nonces, view:{}, seqno:{}",
          nonces.tx_id.view,
          nonces.tx_id.seqno);
        throw ccf_logic_error(fmt::format(
          "Failed to write nonces, view:{}, seqno:{}",
          nonces.tx_id.view,
          nonces.tx_id.seqno));
      }
    }

    std::optional<aft::RevealedNonces> get_nonces() override
    {
      kv::ReadOnlyTx tx(&store);
      auto nonces_tv = tx.ro(revealed_nonces);
      auto nonces = nonces_tv->get(0);
      if (!nonces.has_value())
      {
        LOG_FAIL_FMT("No signatures found in signatures map");
        throw ccf_logic_error("No signatures found in signatures map");
      }
      return nonces;
    }

    bool verify_signature(
      const NodeId& node_id,
      crypto::Sha256Hash& root,
      uint32_t sig_size,
      uint8_t* sig) override
    {
      kv::ReadOnlyTx tx(&store);
      auto ni_tv = tx.ro(nodes);

      auto ni = ni_tv->get(node_id);
      if (!ni.has_value())
      {
        LOG_FAIL_FMT(
          "No node info, and therefore no cert for node {}", node_id);
        return false;
      }
      crypto::VerifierPtr from_cert = crypto::make_verifier(ni.value().cert);
      return from_cert->verify_hash(
        root.h.data(), root.h.size(), sig, sig_size, crypto::MDType::SHA256);
    }

    void sign_view_change_request(
      ViewChangeRequest& view_change, ccf::View view, ccf::SeqNo seqno) override
    {
      crypto::Sha256Hash h = hash_view_change(view_change, view, seqno);
      view_change.signature = kp.sign_hash(h.h.data(), h.h.size());
    }

    bool verify_view_change_request(
      ViewChangeRequest& view_change,
      const NodeId& from,
      ccf::View view,
      ccf::SeqNo seqno) override
    {
      crypto::Sha256Hash h = hash_view_change(view_change, view, seqno);

      kv::ReadOnlyTx tx(&store);
      auto ni_tv = tx.ro(nodes);

      auto ni = ni_tv->get(from);
      if (!ni.has_value())
      {
        LOG_FAIL_FMT("No node info, and therefore no cert for node {}", from);
        return false;
      }
      crypto::VerifierPtr from_cert = crypto::make_verifier(ni.value().cert);
      return from_cert->verify_hash(
        h.h, view_change.signature, crypto::MDType::SHA256);
    }

    bool verify_view_change_request_confirmation(
      ViewChangeConfirmation& new_view, const NodeId& from) override
    {
      kv::ReadOnlyTx tx(&store);
      auto ni_tv = tx.ro(nodes);

      auto ni = ni_tv->get(from);
      if (!ni.has_value())
      {
        LOG_FAIL_FMT("No node info, and therefore no cert for node {}", from);
        return false;
      }
      crypto::VerifierPtr from_cert = crypto::make_verifier(ni.value().cert);
      auto h = hash_new_view(new_view);
      return from_cert->verify_hash(
        h.h, new_view.signature, crypto::MDType::SHA256);
    }

    ccf::SeqNo write_view_change_confirmation(
      ViewChangeConfirmation& new_view) override
    {
      kv::CommittableTx tx(&store);
      auto new_views_tv = tx.rw(new_views);

      crypto::Sha256Hash h = hash_new_view(new_view);
      new_view.signature = kp.sign_hash(h.h.data(), h.h.size());

      new_views_tv->put(0, new_view);
      auto r = tx.commit();
      if (r != kv::CommitResult::SUCCESS)
      {
        LOG_FAIL_FMT(
          "Failed to write new_view, view:{}, seqno:{}",
          new_view.view,
          new_view.seqno);
        throw ccf_logic_error(fmt::format(
          "Failed to write new_view, view:{}, seqno:{}",
          new_view.view,
          new_view.seqno));
      }

      return tx.commit_version();
    }

    crypto::Sha256Hash hash_new_view(ViewChangeConfirmation& new_view)
    {
      auto ch = crypto::make_incremental_sha256();

      ch->update(new_view.view);
      ch->update(new_view.seqno);

      for (auto it : new_view.view_change_messages)
      {
        ch->update(it.second.signature);
      }

      return ch->finalise();
    }

  private:
    kv::AbstractStore& store;
    crypto::KeyPair& kp;
    Nodes nodes;
    BackupSignaturesMap backup_signatures;
    aft::RevealedNoncesMap revealed_nonces;
    NewViewsMap new_views;

    crypto::Sha256Hash hash_view_change(
      const ViewChangeRequest& v, ccf::View view, ccf::SeqNo seqno) const
    {
      auto ch = crypto::make_incremental_sha256();

      ch->update(view);
      ch->update(seqno);

      // ensure that we order the evidence consistently when producing a
      // signature
      //std::map<NodeId, const NodeSignature&> sigs_map;
      //for (auto& s : v.signatures)
      //{
      //  sigs_map.insert({s.node, s});
      //}
      //for (auto& s : sigs_map)
      //{
      //  ch->update(s.second.sig);
      //}

      for (auto& s : v.signatures)
      {
        ch->update(s.sig);
      }

      return ch->finalise();
    }
  };

  static constexpr uint32_t get_message_threshold(uint32_t node_count)
  {
    uint32_t f = 0;
    for (; 3 * f + 1 < node_count; ++f)
      ;

    return 2 * f + 1;
  }
}
