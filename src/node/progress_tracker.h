// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"
#include "ds/ccf_exception.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "nodes.h"
#include "progress_tracker_types.h"
#include "view_change.h"

#include <array>
#include <vector>

namespace ccf
{
  class ProgressTracker
  {
  public:
    ProgressTracker(
      std::shared_ptr<ProgressTrackerStore> store_, kv::NodeId id_) :
      store(store_),
      id(id_),
      entropy(tls::create_entropy())
    {}

    std::shared_ptr<ProgressTrackerStore> store;

    kv::TxHistory::Result add_signature(
      kv::TxID tx_id,
      kv::NodeId node_id,
      uint32_t signature_size,
      std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN>& sig,
      Nonce hashed_nonce,
      uint32_t node_count,
      bool is_primary)
    {
      LOG_TRACE_FMT(
        "add_signature node_id:{}, seqno:{}, hashed_nonce:{}",
        node_id,
        tx_id.version,
        hashed_nonce);
      auto it = certificates.find(tx_id.version);
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r =
          certificates.insert(std::pair<kv::Consensus::SeqNo, CommitCert>(
            tx_id.version, CommitCert()));
        it = r.first;
      }
      else
      {
        if (
          node_id != id && it->second.have_primary_signature &&
          !store->verify_signature(
            node_id, it->second.root, signature_size, sig.data()))
        {
          // NOTE: We need to handle this case but for now having this make a
          // test fail will be very handy
          throw ccf::ccf_logic_error(fmt::format(
            "add_signatures: Signature verification from {} FAILED, view:{}, "
            "seqno:{}",
            node_id,
            tx_id.term,
            tx_id.version));
          return kv::TxHistory::Result::FAIL;
        }
        LOG_TRACE_FMT(
          "Signature verification from {} passed, view:{}, seqno:{}",
          node_id,
          tx_id.term,
          tx_id.version);
      }

      auto& cert = it->second;
      if (cert.wrote_sig_to_ledger)
      {
        LOG_TRACE_FMT(
          "Already wrote append entry view:{}, seqno:{}, ignoring",
          tx_id.term,
          tx_id.version);
        return kv::TxHistory::Result::OK;
      }

      std::vector<uint8_t> sig_vec;
      CCF_ASSERT_FMT(
        signature_size <= sig.size(),
        "Invalid signature size, signature_size:{}, sig.size:{}",
        signature_size,
        sig.size());
      sig_vec.assign(sig.begin(), sig.begin() + signature_size);

      CCF_ASSERT(
        node_id != id ||
          std::equal(
            hashed_nonce.h.begin(),
            hashed_nonce.h.end(),
            get_my_hashed_nonce(tx_id).h.begin()),
        "hashed_nonce does not match my nonce");

      BftNodeSignature bft_node_sig(std::move(sig_vec), node_id, hashed_nonce);
      try_match_unmatched_nonces(
        cert, bft_node_sig, tx_id.term, tx_id.version, node_id);
      cert.sigs.insert(std::pair<kv::NodeId, BftNodeSignature>(
        node_id, std::move(bft_node_sig)));

      if (can_send_sig_ack(cert, tx_id, node_count))
      {
        if (is_primary)
        {
          ccf::BackupSignatures sig_value(tx_id.term, tx_id.version, cert.root);

          for (const auto& sig : cert.sigs)
          {
            if (!sig.second.is_primary)
            {
              sig_value.signatures.push_back(ccf::NodeSignature(
                sig.second.sig, sig.second.node, sig.second.hashed_nonce));
            }
          }

          LOG_TRACE_FMT("Adding signatures to ledger seqno:{}", tx_id.version);
          store->write_backup_signatures(sig_value);
          cert.wrote_sig_to_ledger = true;
        }
        return kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK;
      }
      return kv::TxHistory::Result::OK;
    }

    kv::TxHistory::Result record_primary(
      kv::TxID tx_id,
      kv::NodeId node_id,
      crypto::Sha256Hash& root,
      std::vector<uint8_t>& sig,
      Nonce hashed_nonce,
      uint32_t node_count = 0)
    {
      LOG_TRACE_FMT(
        "record_primary node_id:{}, seqno:{}, hashed_nonce:{}",
        node_id,
        tx_id.version,
        hashed_nonce);
      auto n = entropy->random(hashed_nonce.h.size());
      Nonce my_nonce;
      std::copy(n.begin(), n.end(), my_nonce.h.begin());
      if (node_id == id)
      {
        hash_data(my_nonce, hashed_nonce);
      }

      LOG_TRACE_FMT(
        "record_primary node_id:{}, seqno:{}, hashed_nonce:{}",
        node_id,
        tx_id.version,
        hashed_nonce);

      auto it = certificates.find(tx_id.version);
      if (it == certificates.end())
      {
        CommitCert cert(root, my_nonce);
        cert.have_primary_signature = true;
        BftNodeSignature bft_node_sig(sig, node_id, hashed_nonce);
        bft_node_sig.is_primary = true;
        try_match_unmatched_nonces(
          cert, bft_node_sig, tx_id.term, tx_id.version, node_id);
        cert.sigs.insert(
          std::pair<kv::NodeId, BftNodeSignature>(node_id, bft_node_sig));

        certificates.insert(
          std::pair<kv::Consensus::SeqNo, CommitCert>(tx_id.version, cert));

        LOG_TRACE_FMT(
          "Adding new root for view:{}, seqno:{}", tx_id.term, tx_id.version);
        return kv::TxHistory::Result::OK;
      }
      else
      {
        // We received some entries before we got the root so we now need to
        // verify the signatures
        auto& cert = it->second;
        cert.root = root;
        BftNodeSignature bft_node_sig({}, node_id, hashed_nonce);
        bft_node_sig.is_primary = true;
        try_match_unmatched_nonces(
          cert, bft_node_sig, tx_id.term, tx_id.version, node_id);
        cert.my_nonce = my_nonce;
        cert.have_primary_signature = true;
        for (auto& sig : cert.sigs)
        {
          if (
            !sig.second.is_primary &&
            !store->verify_signature(
              sig.second.node,
              cert.root,
              sig.second.sig.size(),
              sig.second.sig.data()))
          {
            // NOTE: We need to handle this case but for now having this make a
            // test fail will be very handy
            throw ccf::ccf_logic_error(fmt::format(
              "record_primary: Signature verification from {} FAILED, view:{}, "
              "seqno:{}",
              sig.first,
              tx_id.term,
              tx_id.version));
          }
          LOG_TRACE_FMT(
            "Signature verification from {} passed, view:{}, seqno:{}",
            sig.second.node,
            tx_id.term,
            tx_id.version);
        }
        cert.sigs.insert(
          std::pair<kv::NodeId, BftNodeSignature>(node_id, bft_node_sig));
      }

      auto& cert = it->second;
      if (cert.root != root)
      {
        // NOTE: At this point we have cryptographic proof that someone is being
        // dishonest we need to work out what to do.
        throw ccf::ccf_logic_error("We have proof someone is being dishonest");
      }

      if (node_count > 0 && can_send_sig_ack(cert, tx_id, node_count))
      {
        return kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK;
      }
      return kv::TxHistory::Result::OK;
    }

    kv::TxHistory::Result record_primary_signature(
      kv::TxID tx_id, std::vector<uint8_t>& sig)
    {
      auto it = certificates.find(tx_id.version);
      if (it == certificates.end())
      {
        LOG_FAIL_FMT(
          "Adding signature to primary that does not exist view:{}, seqno:{}",
          tx_id.term,
          tx_id.version);
        return kv::TxHistory::Result::FAIL;
      }

      for (auto& cert : it->second.sigs)
      {
        if (!cert.second.is_primary)
        {
          continue;
        }

        cert.second.sig = sig;
        break;
      }

      return kv::TxHistory::Result::OK;
    }

    kv::TxHistory::Result receive_backup_signatures(
      kv::TxID& tx_id, uint32_t node_count, bool is_primary)
    {
      std::optional<ccf::BackupSignatures> sigs =
        store->get_backup_signatures();
      CCF_ASSERT(sigs.has_value(), "sigs does not have a value");
      auto sigs_value = sigs.value();

      auto it = certificates.find(sigs_value.seqno);
      if (it == certificates.end())
      {
        LOG_FAIL_FMT(
          "Primary send backup signatures before sending the primary "
          "signature view:{}, seqno:{}",
          sigs_value.view,
          sigs_value.seqno);
        return kv::TxHistory::Result::FAIL;
      }

      auto& cert = it->second;
      if (!std::equal(
            cert.root.h.begin(), cert.root.h.end(), sigs_value.root.h.begin()))
      {
        LOG_FAIL_FMT(
          "Roots do not match at view:{}, seqno:{}",
          sigs_value.view,
          sigs_value.seqno);
        return kv::TxHistory::Result::FAIL;
      }

      kv::TxHistory::Result success = kv::TxHistory::Result::OK;

      for (auto& backup_sig : sigs_value.signatures)
      {
        auto it = cert.sigs.find(backup_sig.node);
        if (it == cert.sigs.end())
        {
          std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN> sig;
          std::copy(backup_sig.sig.begin(), backup_sig.sig.end(), sig.begin());

          kv::TxHistory::Result r = add_signature(
            {sigs_value.view, sigs_value.seqno},
            backup_sig.node,
            backup_sig.sig.size(),
            sig,
            backup_sig.hashed_nonce,
            node_count,
            is_primary);
          if (r == kv::TxHistory::Result::FAIL)
          {
            return kv::TxHistory::Result::FAIL;
          }
          else if (r == kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK)
          {
            success = kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK;
          }
        }
        else
        {
          if (!std::equal(
                backup_sig.sig.begin(),
                backup_sig.sig.end(),
                it->second.sig.begin()))
          {
            LOG_FAIL_FMT(
              "Signatures do not match at view:{}, seqno:{}, "
              "node_id:{}",
              sigs_value.view,
              sigs_value.seqno,
              backup_sig.node);
            return kv::TxHistory::Result::FAIL;
          }
        }
      }

      tx_id.term = sigs_value.view;
      tx_id.version = sigs_value.seqno;

      return success;
    }

    kv::TxHistory::Result receive_nonces()
    {
      std::optional<aft::RevealedNonces> nonces = store->get_nonces();
      CCF_ASSERT(nonces.has_value(), "nonces does not have a value");
      aft::RevealedNonces& nonces_value = nonces.value();

      auto it = certificates.find(nonces_value.tx_id.version);
      if (it == certificates.end())
      {
        LOG_FAIL_FMT(
          "Primary send backup signatures before sending the primary "
          "signature view:{}, seqno:{}",
          nonces_value.tx_id.term,
          nonces_value.tx_id.version);
        return kv::TxHistory::Result::FAIL;
      }

      auto& cert = it->second;
      for (auto& revealed_nonce : nonces_value.nonces)
      {
        auto it = cert.sigs.find(revealed_nonce.node_id);
        if (it == cert.sigs.end())
        {
          LOG_FAIL_FMT(
            "Node {} sent revealed nonce before sending a signature view:{}, "
            "seqno:{}",
            revealed_nonce.node_id,
            nonces_value.tx_id.term,
            nonces_value.tx_id.version);
          return kv::TxHistory::Result::FAIL;
        }

        BftNodeSignature& commit_cert = it->second;
        auto h = hash_data(revealed_nonce.nonce);
        if (!match_nonces(h, commit_cert.hashed_nonce))
        {
          LOG_FAIL_FMT(
            "Hashed nonces does not match with nonce view:{}, seqno:{}, "
            "node_id:{}",
            nonces_value.tx_id.term,
            nonces_value.tx_id.version,
            revealed_nonce.node_id);
          return kv::TxHistory::Result::FAIL;
        }
        if (cert.nonce_set.find(revealed_nonce.node_id) == cert.nonce_set.end())
        {
          cert.nonce_set.insert(revealed_nonce.node_id);
          std::copy(h.h.begin(), h.h.end(), commit_cert.nonce.h.begin());
        }
      }

      cert.nonces_committed_to_ledger = true;
      try_update_watermark(cert, nonces_value.tx_id.version, true);
      return kv::TxHistory::Result::OK;
    }

    kv::TxHistory::Result add_signature_ack(
      kv::TxID tx_id, kv::NodeId node_id, uint32_t node_count = 0)
    {
      auto it = certificates.find(tx_id.version);
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r =
          certificates.insert(std::pair<kv::Consensus::SeqNo, CommitCert>(
            tx_id.version, CommitCert()));
        it = r.first;
      }

      LOG_TRACE_FMT(
        "processing recv_signature_received_ack, from:{} view:{}, seqno:{}",
        node_id,
        tx_id.term,
        tx_id.version);

      auto& cert = it->second;
      cert.sig_acks.insert(node_id);

      if (can_send_reply_and_nonce(cert, node_count))
      {
        return kv::TxHistory::Result::SEND_REPLY_AND_NONCE;
      }
      return kv::TxHistory::Result::OK;
    }

    void add_nonce_reveal(
      kv::TxID tx_id,
      Nonce nonce,
      kv::NodeId node_id,
      uint32_t node_count,
      bool is_primary)
    {
      bool did_add = false;
      auto it = certificates.find(tx_id.version);
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r =
          certificates.insert(std::pair<kv::Consensus::SeqNo, CommitCert>(
            tx_id.version, CommitCert()));
        it = r.first;
        did_add = true;
      }

      auto& cert = it->second;
      auto it_node_sig = cert.sigs.find(node_id);
      if (it_node_sig == cert.sigs.end())
      {
        cert.unmatched_nonces.insert(
          std::pair<kv::NodeId, Nonce>(node_id, nonce));
        return;
      }

      BftNodeSignature& sig = it_node_sig->second;
      LOG_TRACE_FMT(
        "add_nonce_reveal view:{}, seqno:{}, node_id:{}, sig.hashed_nonce:{}, "
        " received.nonce:{}, hash(received.nonce):{} did_add:{}",
        tx_id.term,
        tx_id.version,
        node_id,
        sig.hashed_nonce,
        nonce,
        hash_data(nonce),
        did_add);

      if (!match_nonces(hash_data(nonce), sig.hashed_nonce))
      {
        // NOTE: We need to handle this case but for now having this make a
        // test fail will be very handy
        LOG_FAIL_FMT(
          "Nonces do not match add_nonce_reveal view:{}, seqno:{}, node_id:{}, "
          "sig.hashed_nonce:{}, "
          " received.nonce:{}, hash(received.nonce):{} did_add:{}",
          tx_id.term,
          tx_id.version,
          node_id,
          sig.hashed_nonce,
          nonce,
          hash_data(nonce),
          did_add);
        throw ccf::ccf_logic_error(fmt::format(
          "nonces do not match verification from {} FAILED, view:{}, seqno:{}",
          node_id,
          tx_id.term,
          tx_id.version));
      }
      sig.nonce = nonce;
      cert.nonce_set.insert(node_id);

      if (should_append_nonces_to_ledger(cert, node_count, is_primary))
      {
        aft::RevealedNonces revealed_nonces(tx_id);

        for (auto nonce_node_id : cert.nonce_set)
        {
          auto it = cert.sigs.find(nonce_node_id);
          CCF_ASSERT_FMT(
            it != cert.sigs.end(),
            "Expected cert not found, node_id:{}",
            nonce_node_id);
          revealed_nonces.nonces.push_back(
            aft::RevealedNonce(nonce_node_id, it->second.nonce));
        }

        store->write_nonces(revealed_nonces);
      }

      try_update_watermark(cert, tx_id.version, is_primary);
    }

    Nonce get_my_nonce(kv::TxID tx_id)
    {
      auto it = certificates.find(tx_id.version);
      if (it == certificates.end())
      {
        throw ccf::ccf_logic_error(fmt::format(
          "Attempting to access unknown nonce, view:{}, seqno:{}",
          tx_id.term,
          tx_id.version));
      }
      return it->second.my_nonce;
    }

    crypto::Sha256Hash get_my_hashed_nonce(kv::TxID tx_id)
    {
      Nonce nonce = get_my_nonce(tx_id);
      return hash_data(nonce);
    }

    void get_my_hashed_nonce(kv::TxID tx_id, crypto::Sha256Hash& hash)
    {
      Nonce nonce = get_my_nonce(tx_id);
      hash_data(nonce, hash);
    }

    void set_node_id(kv::NodeId id_)
    {
      id = id_;
    }

    crypto::Sha256Hash hash_data(Nonce& data)
    {
      crypto::Sha256Hash hash;
      hash_data(data, hash);
      return hash;
    }

    void hash_data(Nonce& data, crypto::Sha256Hash& hash)
    {
      hash = crypto::Sha256Hash({data.h.data(), data.h.size()});
    }

    kv::Consensus::SeqNo get_highest_committed_nonce()
    {
      return highest_commit_level;
    }

    std::tuple<std::unique_ptr<ViewChangeRequest>, kv::Consensus::SeqNo>
    get_view_change_message(kv::Consensus::View view)
    {
      auto it = certificates.find(highest_prepared_level.version);
      if (it == certificates.end())
      {
        throw ccf::ccf_logic_error(fmt::format(
          "Invalid prepared level, view:{}, seqno:{}",
          highest_prepared_level.term,
          highest_prepared_level.version));
      }

      auto& cert = it->second;
      auto m = std::make_unique<ViewChangeRequest>();

      for (const auto& sig : cert.sigs)
      {
        m->signatures.push_back(sig.second);
      }

      store->sign_view_change_request(*m, view, highest_prepared_level.version);
      return std::make_tuple(std::move(m), highest_prepared_level.version);
    }

    bool apply_view_change_message(
      ViewChangeRequest& view_change,
      kv::NodeId from,
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno)
    {
      if (!store->verify_view_change_request(view_change, from, view, seqno))
      {
        LOG_FAIL_FMT("Failed to verify view-change from:{}", from);
        return false;
      }
      LOG_TRACE_FMT(
        "Applying view-change from:{}, view:{}, seqno:{}", from, view, seqno);

      auto it = certificates.find(seqno);

      if (it == certificates.end())
      {
        LOG_INFO_FMT(
          "Received view-change for view:{} and seqno:{} that I am not aware "
          "of",
          view,
          seqno);
        return false;
      }

      bool verified_signatures = true;

      for (auto& sig : view_change.signatures)
      {
        if (!store->verify_signature(
              sig.node, it->second.root, sig.sig.size(), sig.sig.data()))
        {
          LOG_FAIL_FMT(
            "signatures do not match, view-change from:{}, view:{}, seqno:{}, "
            "node_id:{}",
            from,
            view,
            seqno,
            sig.node);
          verified_signatures = false;
          continue;
        }

        if (it->second.sigs.find(sig.node) == it->second.sigs.end())
        {
          continue;
        }
        it->second.sigs.insert(
          std::pair<kv::NodeId, BftNodeSignature>(sig.node, sig));
      }

      return verified_signatures;
    }

    bool apply_new_view(
      kv::NodeId from,
      uint32_t node_count,
      kv::Consensus::View& view_,
      kv::Consensus::SeqNo& seqno_) const
    {
      auto new_view = store->get_new_view();
      CCF_ASSERT(new_view.has_value(), "new view does not have a value");
      kv::Consensus::View view = new_view->view;
      kv::Consensus::SeqNo seqno = new_view->seqno;

      if (
        seqno < highest_prepared_level.version ||
        view < highest_prepared_level.term)
      {
        LOG_FAIL_FMT(
          "Invalid view and seqno in the new view highest prepared from:{}, "
          "view:{},seqno:{}, new_view view:{}, seqno:{}",
          from,
          highest_prepared_level.term,
          highest_prepared_level.version,
          view,
          seqno);
        return false;
      }

      if (
        new_view->view_change_messages.size() <
        ccf::get_message_threshold(node_count))
      {
        LOG_FAIL_FMT(
          "Not enough ViewChangeRequests from:{}, new_view view:{}, seqno:{}, "
          "num_requests:{}",
          from,
          view,
          seqno,
          new_view->view_change_messages.size());
        return false;
      }

      for (auto& vcp : new_view->view_change_messages)
      {
        kv::NodeId id = vcp.first;
        ccf::ViewChangeRequest& vc = vcp.second;

        if (!store->verify_view_change_request(vc, id, view, seqno))
        {
          LOG_FAIL_FMT(
            "Failed to verify view-change id:{},view:{}, seqno:{}",
            id,
            view,
            seqno);
          return false;
        }
      }

      if (!store->verify_view_change_request_confirmation(
            new_view.value(), from))
      {
        LOG_INFO_FMT("Failed to verify from:{}", from);
        return false;
      }

      view_ = view;
      seqno_ = seqno;
      return true;
    }

  private:
    kv::NodeId id;
    std::shared_ptr<tls::Entropy> entropy;
    kv::Consensus::SeqNo highest_commit_level = 0;
    kv::TxID highest_prepared_level = {0, 0};

    std::map<kv::Consensus::SeqNo, CommitCert> certificates;

    void try_match_unmatched_nonces(
      CommitCert& cert,
      BftNodeSignature& bft_node_sig,
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno,
      kv::NodeId node_id)
    {
      auto it_unmatched_nonces = cert.unmatched_nonces.find(node_id);
      if (it_unmatched_nonces != cert.unmatched_nonces.end())
      {
        if (!match_nonces(
              hash_data(it_unmatched_nonces->second),
              bft_node_sig.hashed_nonce))
        {
          // NOTE: We need to handle this case but for now having this make a
          // test fail will be very handy
          LOG_FAIL_FMT(
            "Nonces do not match add_nonce_reveal view:{}, seqno:{}, "
            "node_id:{}, "
            "sig.hashed_nonce:{}, "
            " received.nonce:{}, hash(received.nonce):{}",
            view,
            seqno,
            node_id,
            bft_node_sig.hashed_nonce,
            it_unmatched_nonces->second,
            hash_data(it_unmatched_nonces->second));
          throw ccf::ccf_logic_error(fmt::format(
            "nonces do not match verification from {} FAILED, view:{}, "
            "seqno:{}",
            node_id,
            view,
            seqno));
        }
        bft_node_sig.nonce = it_unmatched_nonces->second;
        cert.nonce_set.insert(node_id);
        cert.unmatched_nonces.erase(it_unmatched_nonces);
      }
    }

    bool match_nonces(const Nonce& n_1, const Nonce& n_2)
    {
      if (n_1.h.size() != n_2.h.size())
      {
        return false;
      }

      return std::equal(n_1.h.begin(), n_1.h.end(), n_2.h.begin());
    }

    bool can_send_sig_ack(
      CommitCert& cert, const kv::TxID& tx_id, uint32_t node_count)
    {
      if (
        cert.sigs.size() >= get_message_threshold(node_count) &&
        !cert.ack_sent && cert.have_primary_signature)
      {
        if (tx_id.version > highest_prepared_level.version)
        {
          CCF_ASSERT_FMT(
            tx_id.term >= highest_prepared_level.term,
            "Prepared terms are moving backwards new_term:{}, current_term:{}",
            tx_id.term,
            highest_prepared_level.term);
          highest_prepared_level = tx_id;
        }

        cert.ack_sent = true;
        return true;
      }
      return false;
    }

    bool can_send_reply_and_nonce(CommitCert& cert, uint32_t node_count)
    {
      if (
        cert.sig_acks.size() >= get_message_threshold(node_count) &&
        !cert.reply_and_nonce_sent && cert.ack_sent)
      {
        cert.reply_and_nonce_sent = true;
        return true;
      }
      return false;
    }

    void try_update_watermark(
      CommitCert& cert,
      kv::Consensus::SeqNo seqno,
      bool should_clear_old_entries)
    {
      if (cert.nonces_committed_to_ledger && seqno > highest_commit_level)
      {
        highest_commit_level = seqno;
        if (should_clear_old_entries)
        {
          LOG_INFO_FMT("Removing all entries upto:{}", seqno);
          for (auto it = certificates.begin();;)
          {
            CCF_ASSERT(
              it != certificates.end(),
              "Should never deleted all certificates");

            if (it->first == seqno)
            {
              break;
            }
            it = certificates.erase(it);
          }
        }
      }
    }

    bool should_append_nonces_to_ledger(
      CommitCert& cert, uint32_t node_count, bool is_primary)
    {
      if (
        cert.nonce_set.size() >= get_message_threshold(node_count) &&
        cert.reply_and_nonce_sent && cert.ack_sent &&
        !cert.nonces_committed_to_ledger)
      {
        cert.nonces_committed_to_ledger = true;
        return is_primary;
      }
      return false;
    }
  };
}