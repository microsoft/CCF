// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/entropy.h"
#include "ds/ccf_assert.h"
#include "ds/ccf_exception.h"
#include "entities.h"
#include "kv/kv_types.h"
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
      std::shared_ptr<ProgressTrackerStore> store_,
      const NodeId& id_,
      bool is_public_only_ = false) :
      store(store_),
      id(id_),
      entropy(crypto::create_entropy()),
      is_public_only(is_public_only_)
    {}

    std::shared_ptr<ProgressTrackerStore> store;

    kv::TxHistory::Result add_signature(
      ccf::TxID tx_id,
      const NodeId& node_id,
      uint32_t signature_size,
      std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN>& sig,
      Nonce hashed_nonce,
      kv::Configuration::Nodes& config,
      bool is_primary)
    {
      std::unique_lock<std::mutex> guard(lock);
      return add_signature_internal(
        tx_id,
        node_id,
        signature_size,
        sig,
        hashed_nonce,
        config,
        is_primary);
    }

    kv::TxHistory::Result record_primary(
      ccf::TxID tx_id,
      NodeId node_id,
      bool am_i_primary,
      crypto::Sha256Hash& root,
      std::vector<uint8_t>& sig,
      Nonce hashed_nonce,
      kv::Configuration::Nodes* config = nullptr)
    {
      std::unique_lock<std::mutex> guard(lock);
      auto n = entropy->random(hashed_nonce.h.size());
      Nonce my_nonce;
      std::copy(n.begin(), n.end(), my_nonce.h.begin());
      if (node_id == id)
      {
        hash_data(my_nonce, hashed_nonce);
      }

      LOG_TRACE_FMT(
        "record_primary node_id:{}, seqno:{}, hashed_nonce:{}, root:{}, sig:{}",
        node_id,
        tx_id.seqno,
        hashed_nonce,
        root,
        sig);

      auto it = certificates.find(tx_id);
      if (it == certificates.end() || am_i_primary)
      {
        // If a primary is behind and becomes a backup (without becoming aware
        // of this) the old primary could attempt to sign a seqno that the new
        // primary signed. In this case clear any prepares that we could have
        // received.
        if (it != certificates.end())
        {
          certificates.erase(it);
        }

        CommitCert cert(root, my_nonce);
        cert.have_primary_signature = true;
        BftNodeSignature bft_node_sig(sig, node_id, hashed_nonce);
        bft_node_sig.is_primary = true;
        try_match_unmatched_nonces(
          cert, bft_node_sig, tx_id.view, tx_id.seqno, node_id);
        cert.sigs.insert(
          std::pair<NodeId, BftNodeSignature>(node_id, bft_node_sig));

        certificates.insert(
          std::pair<ccf::TxID, CommitCert>(tx_id, cert));

        LOG_TRACE_FMT(
          "Adding new root for view:{}, seqno:{}", tx_id.view, tx_id.seqno);
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
          cert, bft_node_sig, tx_id.view, tx_id.seqno, node_id);
        cert.my_nonce = my_nonce;
        cert.have_primary_signature = true;
        for (auto sig = cert.sigs.begin(); sig != cert.sigs.end();)
        {
          if (
            !sig->second.is_primary &&
            !store->verify_signature(
              sig->second.node,
              cert.root,
              sig->second.sig.size(),
              sig->second.sig.data()))
          {
            sig = cert.sigs.erase(sig);
          }
          else
          {
            LOG_TRACE_FMT(
              "Signature verification from {} passed, view:{}, seqno:{}",
              sig->second.node,
              tx_id.view,
              tx_id.seqno);
            ++sig;
          }
        }
        cert.sigs.insert(
          std::pair<NodeId, BftNodeSignature>(node_id, bft_node_sig));
      }

      auto& cert = it->second;
      if (cert.root != root)
      {
        // NOTE: At this point we have cryptographic proof that someone is being
        // dishonest we need to work out what to do.
        throw ccf::ccf_logic_error("We have proof someone is being dishonest");
      }

      if (config != nullptr && config->size() > 0 && can_send_sig_ack(cert, tx_id, *config))
      {
        return !is_public_only ? kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK :
                                 kv::TxHistory::Result::OK;
      }
      return kv::TxHistory::Result::OK;
    }

    kv::TxHistory::Result record_primary_signature(
      ccf::TxID tx_id, std::vector<uint8_t>& sig)
    {
      std::unique_lock<std::mutex> guard(lock);
      auto it = certificates.find(tx_id);
      if (it == certificates.end())
      {
        LOG_FAIL_FMT(
          "Adding signature to primary that does not exist view:{}, seqno:{}",
          tx_id.view,
          tx_id.seqno);
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
      ccf::TxID& tx_id, kv::Configuration::Nodes& config, bool is_primary)
    {
      std::unique_lock<std::mutex> guard(lock);
      std::optional<ccf::BackupSignatures> sigs =
        store->get_backup_signatures();
      CCF_ASSERT(sigs.has_value(), "sigs does not have a value");
      auto sigs_value = sigs.value();

      auto it = certificates.find({sigs_value.view, sigs_value.seqno});
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
          "Roots do not match at view:{}, seqno:{}, cert.root:{}, "
          "sigs_value.root:{}",
          sigs_value.view,
          sigs_value.seqno,
          cert.root,
          sigs_value.root);
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

          kv::TxHistory::Result r = add_signature_internal(
            {sigs_value.view, sigs_value.seqno},
            backup_sig.node,
            backup_sig.sig.size(),
            sig,
            backup_sig.hashed_nonce,
            config,
            is_primary);
          if (r == kv::TxHistory::Result::FAIL)
          {
            return kv::TxHistory::Result::FAIL;
          }
          else if (r == kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK)
          {
            success = !is_public_only ?
              kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK :
              kv::TxHistory::Result::OK;
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

      tx_id.view = sigs_value.view;
      tx_id.seqno = sigs_value.seqno;

      return success;
    }

    kv::TxHistory::Result receive_nonces()
    {
      std::unique_lock<std::mutex> guard(lock);
      std::optional<aft::RevealedNonces> nonces = store->get_nonces();
      CCF_ASSERT(nonces.has_value(), "nonces does not have a value");
      aft::RevealedNonces& nonces_value = nonces.value();

      auto it = certificates.find(nonces_value.tx_id);
      if (it == certificates.end())
      {
        LOG_FAIL_FMT(
          "Primary send backup signatures before sending the primary "
          "signature view:{}, seqno:{}",
          nonces_value.tx_id.view,
          nonces_value.tx_id.seqno);
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
            nonces_value.tx_id.view,
            nonces_value.tx_id.seqno);
          return kv::TxHistory::Result::FAIL;
        }

        BftNodeSignature& commit_cert = it->second;
        auto h = hash_data(revealed_nonce.nonce);
        if (!match_nonces(h, commit_cert.hashed_nonce))
        {
          LOG_FAIL_FMT(
            "Hashed nonces does not match with nonce view:{}, seqno:{}, "
            "node_id:{}",
            nonces_value.tx_id.view,
            nonces_value.tx_id.seqno,
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
      try_update_watermark(cert, nonces_value.tx_id.seqno, true);
      return kv::TxHistory::Result::OK;
    }

    kv::TxHistory::Result add_signature_ack(
      ccf::TxID tx_id, const NodeId& node_id, kv::Configuration::Nodes* config = nullptr)
    {
      std::unique_lock<std::mutex> guard(lock);
      auto it = certificates.find(tx_id);
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r = certificates.insert(
          std::pair<ccf::TxID, CommitCert>(tx_id, CommitCert()));
        it = r.first;
      }

      LOG_TRACE_FMT(
        "processing recv_signature_received_ack, from:{} view:{}, seqno:{}",
        node_id,
        tx_id.view,
        tx_id.seqno);

      auto& cert = it->second;
      cert.sig_acks.insert(node_id);

      if (can_send_reply_and_nonce(cert, *config))
      {
        return !is_public_only ? kv::TxHistory::Result::SEND_REPLY_AND_NONCE :
                                 kv::TxHistory::Result::OK;
      }
      return kv::TxHistory::Result::OK;
    }

    void add_nonce_reveal(
      ccf::TxID tx_id,
      Nonce nonce,
      const NodeId& node_id,
      kv::Configuration::Nodes& config,
      bool is_primary)
    {
      std::unique_lock<std::mutex> guard(lock);
      bool did_add = false;
      auto it = certificates.find(tx_id);
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r = certificates.insert(
          std::pair<ccf::TxID, CommitCert>(tx_id, CommitCert()));
        it = r.first;
        did_add = true;
      }

      auto& cert = it->second;
      auto it_node_sig = cert.sigs.find(node_id);
      if (it_node_sig == cert.sigs.end())
      {
        cert.unmatched_nonces.insert(std::pair<NodeId, Nonce>(node_id, nonce));
        return;
      }

      BftNodeSignature& sig = it_node_sig->second;
      LOG_TRACE_FMT(
        "add_nonce_reveal view:{}, seqno:{}, node_id:{}, sig.hashed_nonce:{}, "
        " received.nonce:{}, hash(received.nonce):{} did_add:{}",
        tx_id.view,
        tx_id.seqno,
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
          tx_id.view,
          tx_id.seqno,
          node_id,
          sig.hashed_nonce,
          nonce,
          hash_data(nonce),
          did_add);
        throw ccf::ccf_logic_error(fmt::format(
          "nonces do not match verification from {} FAILED, view:{}, seqno:{}",
          node_id,
          tx_id.view,
          tx_id.seqno));
      }
      sig.nonce = nonce;
      cert.nonce_set.insert(node_id);

      if (should_append_nonces_to_ledger(cert, config, is_primary))
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

      try_update_watermark(cert, tx_id.seqno, is_primary);
    }

    std::optional<crypto::Sha256Hash> get_node_hashed_nonce(ccf::TxID tx_id)
    {
      std::unique_lock<std::mutex> guard(lock);
      return get_node_hashed_nonce_internal(tx_id);
    }

    void get_node_hashed_nonce(ccf::TxID tx_id, std::optional<crypto::Sha256Hash>& hash)
    {
      std::optional<Nonce> nonce = get_node_nonce(tx_id);
      if (nonce.has_value())
      {
        crypto::Sha256Hash h;
        hash_data(nonce.value(), h);
        hash = h;
      }
    }

    void set_node_id(const NodeId& id_)
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

    ccf::SeqNo get_highest_committed_nonce()
    {
      return highest_commit_level;
    }

    std::tuple<std::unique_ptr<ViewChangeRequest>, ccf::SeqNo>
    get_view_change_message(ccf::View view)
    {
      std::unique_lock<std::mutex> guard(lock);
      auto it = certificates.find(highest_prepared_level);
      if (it == certificates.end())
      {
        throw ccf::ccf_logic_error(fmt::format(
          "Invalid prepared level, view:{}, seqno:{}",
          highest_prepared_level.view,
          highest_prepared_level.seqno));
      }

      auto& cert = it->second;
      auto m = std::make_unique<ViewChangeRequest>();
      m->seqno = highest_prepared_level.seqno;
      m->root = cert.root;

      for (const auto& sig : cert.sigs)
      {
        // We may have received a nonce but not the signature from a
        // node, in this case we do not want to include the empty signature
        if (!sig.second.sig.empty())
        {
          m->signatures.push_back(sig.second);
        }
      }

      store->sign_view_change_request(*m, view);
      LOG_INFO_FMT(
        "Creating ViewChangeRequest view:{}, seqno:{}, root:{}, sig.size:{}, "
        "sig:{}",
        view,
        m->seqno,
        m->root,
        m->signature.size(),
        m->signature);
      return std::make_tuple(std::move(m), highest_prepared_level.seqno);
    }

    enum class ApplyViewChangeMessageResult
    {
      OK = 1,
      FAIL,
      SKIP_VIEW
    };

    ApplyViewChangeMessageResult apply_view_change_message(
      ViewChangeRequest& view_change,
      const NodeId& from,
      ccf::View view,
      ccf::SeqNo seqno)
    {
      std::unique_lock<std::mutex> guard(lock);
      if (seqno > highest_prepared_level.seqno)
      {
        LOG_INFO_FMT(
          "view-change seqno:{}, my_prepared_seqno:{}, from:{}",
          seqno,
          highest_prepared_level.seqno,
          from);
        return ApplyViewChangeMessageResult::SKIP_VIEW;
      }

      if (!store->verify_view_change_request(view_change, from, view, seqno))
      {
        LOG_FAIL_FMT("Failed to verify view-change from:{}", from);
        return ApplyViewChangeMessageResult::FAIL;
      }
      LOG_INFO_FMT(
        "Applying view-change from:{}, view:{}, seqno:{}", from, view, seqno);
      bool verified_signatures = true;

      for (auto& sig : view_change.signatures)
      {
        if (!store->verify_signature(
              sig.node, view_change.root, sig.sig.size(), sig.sig.data()))
        {
          LOG_FAIL_FMT(
            "signatures do not match, view-change from:{}, view:{}, seqno:{}, "
            "node_id:{}, root:{}, sig:{}, sig.size:{}",
            from,
            view,
            seqno,
            sig.node,
            view_change.root,
            sig.sig,
            sig.sig.size());
          verified_signatures = false;
          continue;
        }
      }

      return verified_signatures ? ApplyViewChangeMessageResult::OK :
                                   ApplyViewChangeMessageResult::FAIL;
    }

    bool apply_new_view(
      kv::Configuration::Nodes& config, ccf::View& view_)
    {
      std::unique_lock<std::mutex> guard(lock);
      auto new_view = store->get_new_view();
      CCF_ASSERT(new_view.has_value(), "new view does not have a value");
      ccf::View view = new_view->view;
      ccf::NodeId from = new_view->primary_id;

      if (
        new_view->view_change_messages.size() <
        ccf::get_message_threshold(config.size()))
      {
        LOG_FAIL_FMT(
          "Not enough ViewChangeRequests from:{}, new_view view:{}, "
          "num_requests:{}",
          from,
          view,
          new_view->view_change_messages.size());
        return false;
      }

      for (auto& vcp : new_view->view_change_messages)
      {
        NodeId id = vcp.first;
        ccf::ViewChangeRequest& vc = vcp.second;

        bool result = store->verify_view_change_request(vc, id, view, vc.seqno);
        LOG_INFO_FMT(
          "Verify view-change id:{},view:{}, seqno:{}, from:{}, result:{}",
          id,
          view,
          vc.seqno,
          from,
          result);
        if (!result)
        {
          LOG_FAIL_FMT(
            "Failed to verify view-change id:{},view:{}, seqno:{}, from:{}",
            id,
            view,
            vc.seqno,
            from);
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
      return true;
    }

    std::optional<Nonce> get_node_nonce(ccf::TxID tx_id)
    {
      std::unique_lock<std::mutex> guard(lock);
      return get_node_nonce_(tx_id);
    }

    void rollback(ccf::SeqNo rollback_seqno, ccf::View view)
    {
      std::unique_lock<std::mutex> guard(lock);
      ccf::SeqNo last_good_seqno = 0;
      for (auto it = certificates.begin(); it != certificates.end();)
      {
        if (it->first.seqno > rollback_seqno)
        {
          it = certificates.erase(it);
        }
        else
        {
          if(last_good_seqno < it->first.seqno) 
          {
            last_good_seqno = it->first.seqno;
          }
          ++it;
        }
      }

      if (certificates.empty())
      {
        highest_prepared_level = {0, 0};
      }
      else if (highest_prepared_level.seqno > last_good_seqno)
      {
        highest_prepared_level = {view, last_good_seqno};
      }
    }

    ccf::SeqNo get_rollback_seqno() const
    {
      std::unique_lock<std::mutex> guard(lock);
      return highest_commit_level;
    }

    void set_is_public_only(bool public_only)
    {
      std::unique_lock<std::mutex> guard(lock);
      is_public_only = public_only;
    }

    std::tuple<ccf::NodeId, ccf::View> get_primary_at_last_view_change()
    {
      std::unique_lock<std::mutex> guard(lock);
      auto new_view = store->get_new_view();
      if (!new_view.has_value())
      {
        return std::make_tuple<ccf::NodeId, ccf::View>(
          ccf::NodeId(fmt::format("{:#064}", 0)), 0);
      }
      return std::make_tuple<ccf::NodeId, ccf::View>(
        NodeId(new_view->primary_id), View(new_view->view));
    }

  private:
    NodeId id;
    std::shared_ptr<crypto::Entropy> entropy;
    ccf::SeqNo highest_commit_level = 0;
    ccf::TxID highest_prepared_level = {0, 0};

    //std::map<ccf::SeqNo, CommitCert> certificates;

    struct classcomp
    {
      bool operator()(const ccf::TxID& lhs, const ccf::TxID& rhs) const
      {
        if(lhs.view == rhs.view)
        {
          return lhs.seqno < rhs.seqno;
        }
        return lhs.view < rhs.view;
      }
    };

    std::map<ccf::TxID, CommitCert, classcomp> certificates;
    bool is_public_only;
    mutable std::mutex lock;

    kv::TxHistory::Result add_signature_internal(
      ccf::TxID tx_id,
      const NodeId& node_id,
      uint32_t signature_size,
      std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN>& sig,
      Nonce hashed_nonce,
      kv::Configuration::Nodes& config,
      bool is_primary)
    {
      LOG_TRACE_FMT(
        "add_signature node_id:{}, seqno:{}, hashed_nonce:{}",
        node_id,
        tx_id.seqno,
        hashed_nonce);
      auto it = certificates.find(tx_id);
      if (it == certificates.end())
      {
        // At this point the appropriate Merkle root is not known. The signature
        // will be recorded and verified when the primary sends the apporiate
        // Merkle root.
        auto r = certificates.insert(
          std::pair<ccf::TxID, CommitCert>(tx_id, CommitCert()));
        it = r.first;
      }
      else
      {
        if (
          node_id != id && it->second.have_primary_signature &&
          !store->verify_signature(
            node_id, it->second.root, signature_size, sig.data()))
        {
          throw ccf::ccf_logic_error(fmt::format(
            "add_signatures: Signature verification from {} FAILED, view:{}, "
            "seqno:{}",
            node_id,
            tx_id.view,
            tx_id.seqno));
          return kv::TxHistory::Result::FAIL;
        }
        LOG_TRACE_FMT(
          "Signature verification from {} passed, view:{}, seqno:{}",
          node_id,
          tx_id.view,
          tx_id.seqno);
      }

      auto& cert = it->second;
      if (cert.wrote_sig_to_ledger)
      {
        LOG_TRACE_FMT(
          "Already wrote append entry view:{}, seqno:{}, ignoring",
          tx_id.view,
          tx_id.seqno);
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
          (get_node_hashed_nonce_internal(tx_id).has_value() &&
           std::equal(
             hashed_nonce.h.begin(),
             hashed_nonce.h.end(),
             get_node_hashed_nonce_internal(tx_id)->h.begin())),
        "hashed_nonce does not match the local node's nonce");

      BftNodeSignature bft_node_sig(std::move(sig_vec), node_id, hashed_nonce);
      try_match_unmatched_nonces(
        cert, bft_node_sig, tx_id.view, tx_id.seqno, node_id);
      cert.sigs.insert(
        std::pair<NodeId, BftNodeSignature>(node_id, std::move(bft_node_sig)));

      if (can_send_sig_ack(cert, tx_id, config))
      {
        if (is_primary)
        {
          ccf::BackupSignatures sig_value(tx_id.view, tx_id.seqno, cert.root);

          for (const auto& sig : cert.sigs)
          {
            if (!sig.second.is_primary)
            {
              sig_value.signatures.push_back(ccf::NodeSignature(
                sig.second.sig, sig.second.node, sig.second.hashed_nonce));
            }
          }

          LOG_TRACE_FMT("Adding signatures to ledger seqno:{}", tx_id.seqno);
          store->write_backup_signatures(sig_value);
          cert.wrote_sig_to_ledger = true;
        }
        return !is_public_only ? kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK :
                                 kv::TxHistory::Result::OK;
      }
      return kv::TxHistory::Result::OK;
    }

    std::optional<Nonce> get_node_nonce_(ccf::TxID tx_id)
    {
      auto it = certificates.find(tx_id);
      if (it == certificates.end())
      {
        return std::nullopt;
      }
      return it->second.my_nonce;
    }

    std::optional<crypto::Sha256Hash> get_node_hashed_nonce_internal(ccf::TxID tx_id)
    {
      std::optional<Nonce> nonce = get_node_nonce_(tx_id);
      if (!nonce.has_value())
      {
        return std::nullopt;
      }
      return hash_data(nonce.value());
    }

    void try_match_unmatched_nonces(
      CommitCert& cert,
      BftNodeSignature& bft_node_sig,
      ccf::View view,
      ccf::SeqNo seqno,
      const NodeId& node_id)
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
      CommitCert& cert, const ccf::TxID& tx_id, kv::Configuration::Nodes& config)
    {
      if (
        cert.sigs.size() >= get_message_threshold(config.size()) &&
        !cert.ack_sent && cert.have_primary_signature)
      {
        if (tx_id.seqno > highest_prepared_level.seqno)
        {
          if (tx_id.view < highest_prepared_level.view)
          {
            LOG_INFO_FMT(
              "Prepared terms are moving backwards new_term:{}, "
              "current_term:{}",
              tx_id.view,
              highest_prepared_level.view);
            return false;
          }
          highest_prepared_level = tx_id;
        }

        cert.ack_sent = true;
        return true;
      }
      return false;
    }

    bool can_send_reply_and_nonce(CommitCert& cert, kv::Configuration::Nodes& config)
    {
      if (
        cert.sig_acks.size() >= get_message_threshold(config.size()) &&
        !cert.reply_and_nonce_sent && cert.ack_sent)
      {
        cert.reply_and_nonce_sent = true;
        return true;
      }
      return false;
    }

    void try_update_watermark(
      CommitCert& cert, ccf::SeqNo seqno, bool should_clear_old_entries)
    {
      if (cert.nonces_committed_to_ledger && seqno > highest_commit_level)
      {
        highest_commit_level = seqno;
        if (should_clear_old_entries)
        {
          LOG_DEBUG_FMT("Removing all entries upto:{}", seqno);
          for (auto it = certificates.begin(); it != certificates.end();)
          {
            if (it->first.seqno >= seqno)
            {
              ++it;
            }
            else
            {
              it = certificates.erase(it);
            }
          }
          CCF_ASSERT(
            !certificates.empty(), "Should never deleted all certificates");
        }
      }
    }

    bool should_append_nonces_to_ledger(
      CommitCert& cert, kv::Configuration::Nodes& config, bool is_primary)
    {
      if (
        cert.nonce_set.size() >= get_message_threshold(config.size()) &&
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