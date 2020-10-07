// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"
#include "ds/ccf_exception.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "nodes.h"
#include "progress_tracker_types.h"

#include <array>
#include <vector>

namespace ccf
{
  class ProgressTracker
  {
  public:
    ProgressTracker(
      std::unique_ptr<ProgressTrackerStore> store_, kv::NodeId id_) :
      store(std::move(store_)),
      id(id_),
      entropy(tls::create_entropy())
    {}

    std::unique_ptr<ProgressTrackerStore> store;

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
      auto it = certificates.find(CertKey(tx_id));
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r = certificates.insert(
          std::pair<CertKey, CommitCert>(CertKey(tx_id), CommitCert()));
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

      std::vector<uint8_t> sig_vec;
      CCF_ASSERT_FMT(
        signature_size <= sig.size(),
        "Invalid signature size, signature_size:{}, sig.size:{}",
        signature_size,
        sig.size());
      sig_vec.assign(sig.begin(), sig.begin() + signature_size);

      auto& cert = it->second;
      CCF_ASSERT(
        node_id != id ||
          std::equal(
            hashed_nonce.begin(),
            hashed_nonce.end(),
            get_my_hashed_nonce(tx_id).begin()),
        "hashed_nonce does not match my nonce");

      BftNodeSignature bft_node_sig(std::move(sig_vec), node_id, hashed_nonce);
      try_match_unmatched_nonces(
        cert, bft_node_sig, tx_id.term, tx_id.version, node_id);
      cert.sigs.insert(std::pair<kv::NodeId, BftNodeSignature>(
        node_id, std::move(bft_node_sig)));

      if (can_send_sig_ack(cert, node_count))
      {
        if (is_primary)
        {
          const CertKey& key = it->first;
          ccf::BackupSignatures sig_value(
            key.tx_id.term, key.tx_id.version, cert.root);

          for (const auto& sig : cert.sigs)
          {
            if (!sig.second.is_primary)
            {
              sig_value.signatures.push_back(ccf::NodeSignature(
                sig.second.sig, sig.second.node, sig.second.hashed_nonce));
            }
          }

          store->write_backup_signatures(sig_value);
        }
        return kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK;
      }
      return kv::TxHistory::Result::OK;
    }

    kv::TxHistory::Result record_primary(
      kv::TxID tx_id,
      kv::NodeId node_id,
      crypto::Sha256Hash& root,
      Nonce hashed_nonce,
      uint32_t node_count = 0)
    {
      LOG_TRACE_FMT(
        "record_primary node_id:{}, seqno:{}, hashed_nonce:{}",
        node_id,
        tx_id.version,
        hashed_nonce);
      auto n = entropy->random(hashed_nonce.size());
      Nonce my_nonce;
      std::copy(n.begin(), n.end(), my_nonce.begin());
      if (node_id == id)
      {
        auto h = hash_data(my_nonce);
        std::copy(h.begin(), h.end(), hashed_nonce.begin());
      }

      LOG_TRACE_FMT(
        "record_primary node_id:{}, seqno:{}, hashed_nonce:{}",
        node_id,
        tx_id.version,
        hashed_nonce);

      auto it = certificates.find(CertKey(tx_id));
      if (it == certificates.end())
      {
        CommitCert cert(root, my_nonce);
        cert.have_primary_signature = true;
        BftNodeSignature bft_node_sig({}, node_id, hashed_nonce);
        bft_node_sig.is_primary = true;
        try_match_unmatched_nonces(
          cert, bft_node_sig, tx_id.term, tx_id.version, node_id);
        cert.sigs.insert(
          std::pair<kv::NodeId, BftNodeSignature>(node_id, bft_node_sig));

        certificates.insert(
          std::pair<CertKey, CommitCert>(CertKey(tx_id), cert));

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

      if (node_count > 0 && can_send_sig_ack(cert, node_count))
      {
        return kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK;
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

      auto it = certificates.find(CertKey({sigs_value.view, sigs_value.seqno}));
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

      auto it = certificates.find(CertKey(nonces_value.tx_id));
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
            "Primary sent revealed nonce before sending a signature view:{}, "
            "seqno:{}",
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
          std::copy(h.begin(), h.end(), commit_cert.nonce.begin());
        }
      }
      return kv::TxHistory::Result::OK;
    }

    kv::TxHistory::Result add_signature_ack(
      kv::TxID tx_id, kv::NodeId node_id, uint32_t node_count = 0)
    {
      auto it = certificates.find(CertKey(tx_id));
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r = certificates.insert(
          std::pair<CertKey, CommitCert>(CertKey(tx_id), CommitCert()));
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
      auto it = certificates.find(CertKey(tx_id));
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r = certificates.insert(
          std::pair<CertKey, CommitCert>(CertKey(tx_id), CommitCert()));
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

      if (is_primary && should_append_nonces_to_ledger(cert, node_count))
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
    }

    Nonce get_my_nonce(kv::TxID tx_id)
    {
      auto it = certificates.find(CertKey(tx_id));
      if (it == certificates.end())
      {
        throw ccf::ccf_logic_error(fmt::format(
          "Attempting to access unknown nonce, view:{}, seqno:{}",
          tx_id.term,
          tx_id.version));
      }
      return it->second.my_nonce;
    }

    std::vector<uint8_t> get_my_hashed_nonce(kv::TxID tx_id)
    {
      Nonce nonce = get_my_nonce(tx_id);
      return hash_data(nonce);
    }

    void set_node_id(kv::NodeId id_)
    {
      id = id_;
    }

    std::vector<uint8_t> hash_data(Nonce& data)
    {
      tls::HashBytes hash;
      tls::do_hash(
        reinterpret_cast<const uint8_t*>(&data),
        data.size(),
        hash,
        MBEDTLS_MD_SHA256);
      return hash;
    }

    kv::Consensus::SeqNo get_highest_commit_level()
    {
      auto it = certificates.find(highest_commit_level);
      if (it == certificates.end())
      {
        highest_commit_level = {0, 0};
        it = certificates.begin();
      }

      for (; it != certificates.end(); ++it)
      {
        CommitCert& cert = it->second;
        if (cert.nonces_committed_to_ledger == false)
        {
          break;
        }
        highest_commit_level = it->first.tx_id;
      }

      return highest_commit_level.version;
    }

  private:
    kv::NodeId id;
    std::shared_ptr<tls::Entropy> entropy;
    kv::TxID highest_commit_level = {0, 0};

    std::map<CertKey, CommitCert> certificates;

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

    bool match_nonces(std::vector<uint8_t> n_1, Nonce n_2)
    {
      if (n_1.size() != n_2.size())
      {
        return false;
      }

      return std::equal(n_1.begin(), n_1.end(), n_2.begin());
    }

    uint32_t get_message_threshold(uint32_t node_count)
    {
      uint32_t f = 0;
      for (; 3 * f + 1 < node_count; ++f)
        ;

      return 2 * f + 1;
    }

    bool can_send_sig_ack(CommitCert& cert, uint32_t node_count)
    {
      if (
        cert.sigs.size() >= get_message_threshold(node_count) &&
        !cert.ack_sent && cert.have_primary_signature)
      {
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

    bool should_append_nonces_to_ledger(CommitCert& cert, uint32_t node_count)
    {
      if (
        cert.nonce_set.size() >= get_message_threshold(node_count) &&
        cert.reply_and_nonce_sent && cert.ack_sent &&
        !cert.nonces_committed_to_ledger)
      {
        cert.nonces_committed_to_ledger = true;
        return true;
      }
      return false;
    }
  };
}