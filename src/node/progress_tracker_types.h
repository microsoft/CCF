// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "backup_signatures.h"
#include "consensus/aft/revealed_nonces.h"
#include "crypto/hash.h"
#include "crypto/verifier.h"
#include "ds/thread_messaging.h"
#include "node_signature.h"
#include "tls/tls.h"
#include "view_change.h"

namespace ccf
{
  struct BftNodeSignature : public ccf::NodeSignature
  {
    bool is_primary;
    Nonce nonce;
    crypto::Sha256Hash root;

    BftNodeSignature(const NodeSignature& ns) :
      NodeSignature(ns),
      is_primary(false)
    {}

    BftNodeSignature(
      const std::vector<uint8_t>& sig_,
      NodeId node_,
      Nonce hashed_nonce_,
      crypto::Sha256Hash& root_) :
      NodeSignature(sig_, node_, hashed_nonce_),
      is_primary(false),
      root(root_)
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
    bool wrote_sig_to_ledger = false;
  };

  class ProgressTrackerStore
  {
  public:
    virtual ~ProgressTrackerStore() = default;
    virtual void write_backup_signatures(ccf::BackupSignatures& sig_value) = 0;
    virtual std::optional<ccf::BackupSignatures> get_backup_signatures() = 0;
    virtual std::optional<ccf::ViewChangeConfirmation> get_new_view() = 0;
    virtual void write_nonces(aft::RevealedNonces& nonces) = 0;
    virtual std::optional<aft::RevealedNonces> get_nonces() = 0;
    virtual bool verify_signature(
      kv::NodeId node_id,
      crypto::Sha256Hash& root,
      uint32_t sig_size,
      uint8_t* sig) = 0;
    virtual void sign_view_change_request(
      ViewChangeRequest& view_change,
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno) = 0;
    virtual bool verify_view_change_request(
      ViewChangeRequest& view_change,
      kv::NodeId from,
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno) = 0;
    virtual kv::Consensus::SeqNo write_view_change_confirmation(
      ccf::ViewChangeConfirmation& new_view) = 0;
    virtual bool verify_view_change_request_confirmation(
      ccf::ViewChangeConfirmation& new_view, kv::NodeId from) = 0;
  };

  class ProgressTrackerStoreAdapter : public ProgressTrackerStore
  {
  public:
    ProgressTrackerStoreAdapter(
      kv::AbstractStore& store_, crypto::KeyPair& kp_) :
      store(store_),
      kp(kp_),
      nodes(ccf::Tables::NODES),
      backup_signatures(ccf::Tables::BACKUP_SIGNATURES),
      revealed_nonces(ccf::Tables::NONCES),
      new_views(ccf::Tables::NEW_VIEWS)
    {}


    struct WriteBackupSigs
    {
      WriteBackupSigs(
      ccf::BackupSignatures sig_value_,
      ProgressTrackerStoreAdapter* self_) : sig_value(std::move(sig_value_)), self(self_) {}
      
      ccf::BackupSignatures sig_value;
      ProgressTrackerStoreAdapter* self;
    };

    void write_backup_signatures(ccf::BackupSignatures& sig_value) override
    {
      if(threading::ThreadMessaging::thread_count > 1)
      {
        auto msg = std::make_unique<threading::Tmsg<WriteBackupSigs>>(
          [](std::unique_ptr<threading::Tmsg<WriteBackupSigs>> msg) {
            msg->data.self->write_backup_signatures_internal(msg->data.sig_value);
          },
          std::move(sig_value),
          this);

        threading::ThreadMessaging::thread_messaging.add_task(
          threading::ThreadMessaging::get_execution_thread(
            threading::get_current_thread_id()),
          std::move(msg));
      }
      else
      {
        write_backup_signatures_internal(sig_value);
      }
    }

    void write_backup_signatures_internal(ccf::BackupSignatures& sig_value)
    {
      kv::Tx tx(&store);
      auto backup_sig_view = tx.rw(backup_signatures);

      backup_sig_view->put(0, sig_value);
      auto r = tx.commit();
      if (r == kv::CommitResult::FAIL_CONFLICT)
      {
        LOG_FAIL_FMT(
          "Failed to write nonces, view:{}, seqno:{}, r:{}",
          sig_value.view,
          sig_value.seqno,
          r);
        throw ccf::ccf_logic_error(fmt::format(
          "Failed to write nonces, view:{}, seqno:{}, r:{}",
          sig_value.view,
          sig_value.seqno,
          r));
      }
    }

    std::optional<ccf::BackupSignatures> get_backup_signatures() override
    {
      kv::Tx tx(&store);
      auto sigs_tv = tx.rw(backup_signatures);
      auto sigs = sigs_tv->get(0);
      if (!sigs.has_value())
      {
        LOG_FAIL_FMT("No signatures found in signatures map");
        throw ccf::ccf_logic_error("No signatures found in signatures map");
      }
      return sigs;
    }

    std::optional<ccf::ViewChangeConfirmation> get_new_view() override
    {
      kv::Tx tx(&store);
      auto new_views_tv = tx.rw(new_views);
      auto new_view = new_views_tv->get(0);
      if (!new_view.has_value())
      {
        LOG_FAIL_FMT("No new_view found in new_view map");
        throw ccf::ccf_logic_error("No new_view found in new_view map");
      }
      return new_view;
    }

    struct WriteNonces
    {
      WriteNonces(
      aft::RevealedNonces nonces_,
      ProgressTrackerStoreAdapter* self_) : nonces(std::move(nonces_)), self(self_) {}
      
      aft::RevealedNonces nonces;
      ProgressTrackerStoreAdapter* self;
    };

    void write_nonces(aft::RevealedNonces& nonces) override
    {
      if(threading::ThreadMessaging::thread_count > 1)
      {
        auto msg = std::make_unique<threading::Tmsg<WriteNonces>>(
          [](std::unique_ptr<threading::Tmsg<WriteNonces>> msg) {
            msg->data.self->write_nonces_internal(msg->data.nonces);
          },
          std::move(nonces),
          this);

        threading::ThreadMessaging::thread_messaging.add_task(
          threading::ThreadMessaging::get_execution_thread(
            threading::get_current_thread_id()),
          std::move(msg));
      }
      else
      {
        write_nonces_internal(nonces);
      }
    }

    void write_nonces_internal(aft::RevealedNonces& nonces)
    {
      kv::Tx tx(&store);
      auto nonces_tv = tx.rw(revealed_nonces);

      nonces_tv->put(0, nonces);
      auto r = tx.commit();
      if (r == kv::CommitResult::FAIL_CONFLICT)
      {
        LOG_FAIL_FMT(
          "Failed to write nonces, view:{}, seqno:{}, r:{}",
          nonces.tx_id.term,
          nonces.tx_id.version,
          r);
        throw ccf::ccf_logic_error(fmt::format(
          "Failed to write nonces, view:{}, seqno:{}, r:{}",
          nonces.tx_id.term,
          nonces.tx_id.version,
          r));
      }
    }

    std::optional<aft::RevealedNonces> get_nonces() override
    {
      kv::Tx tx(&store);
      auto nonces_tv = tx.rw(revealed_nonces);
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
      auto ni_tv = tx.rw(nodes);

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
      ViewChangeRequest& view_change,
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno) override
    {
      crypto::Sha256Hash h = hash_view_change(view_change, view, seqno);
      view_change.signature = kp.sign_hash(h.h.data(), h.h.size());
    }

    bool verify_view_change_request(
      ViewChangeRequest& view_change,
      kv::NodeId from,
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno) override
    {
      crypto::Sha256Hash h = hash_view_change(view_change, view, seqno);

      kv::Tx tx(&store);
      auto ni_tv = tx.rw(nodes);

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
      ViewChangeConfirmation& new_view, kv::NodeId from) override
    {
      kv::Tx tx(&store);
      auto ni_tv = tx.rw(nodes);

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

    kv::Consensus::SeqNo write_view_change_confirmation(
      ccf::ViewChangeConfirmation& new_view) override
    {
      kv::Tx tx(&store);
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
        throw ccf::ccf_logic_error(fmt::format(
          "Failed to write new_view, view:{}, seqno:{}",
          new_view.view,
          new_view.seqno));
      }

      return tx.commit_version();
    }

    crypto::Sha256Hash hash_new_view(ccf::ViewChangeConfirmation& new_view)
    {
      crypto::ISha256Hash ch;
      ch.update(new_view.view);
      ch.update(new_view.seqno);

      for (auto it : new_view.view_change_messages)
      {
        ch.update(it.second.signature);
      }

      return ch.finalise();
    }

  private:
    kv::AbstractStore& store;
    crypto::KeyPair& kp;
    ccf::Nodes nodes;
    ccf::BackupSignaturesMap backup_signatures;
    aft::RevealedNoncesMap revealed_nonces;
    ccf::NewViewsMap new_views;

    crypto::Sha256Hash hash_view_change(
      const ViewChangeRequest& v,
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno) const
    {
      crypto::ISha256Hash ch;

      ch.update(view);
      ch.update(seqno);

      for (auto& s : v.signatures)
      {
        ch.update(s.sig);
      }

      return ch.finalise();
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
