// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"
#include "ds/ccf_exception.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "node_signature.h"
#include "nodes.h"
#include "tls/hash.h"
#include "tls/tls.h"
#include "tls/verifier.h"

#include <array>
#include <vector>

namespace ccf
{
  class ProgressTracker
  {
  public:
    ProgressTracker(kv::NodeId id_, ccf::Nodes& nodes_) :
      id(id_),
      nodes(nodes_),
      entropy(tls::create_entropy())
    {}

    kv::TxHistory::Result add_signature(
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno,
      kv::NodeId node_id,
      uint32_t signature_size,
      std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN>& sig,
      Nonce& hashed_nonce,
      uint32_t node_count)
    {
      LOG_TRACE_FMT("add_signature node_id:{}, seqno:{}", node_id, seqno);
      auto it = certificates.find(CertKey(view, seqno));
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r = certificates.insert(
          std::pair<CertKey, CommitCert>(CertKey(view, seqno), CommitCert()));
        it = r.first;
      }
      else
      {
        if (
          node_id != id &&
          !verify_signature(
            node_id, it->second.root, signature_size, sig.data()))
        {
          // NOTE: We need to handle this case but for now having this make a
          // test fail will be very handy
          throw ccf::ccf_logic_error(fmt::format(
            "Signature verification from {} FAILED, view:{}, seqno:{}",
            node_id,
            view,
            seqno));
          return kv::TxHistory::Result::FAIL;
        }
        LOG_TRACE_FMT(
          "Signature verification from {} passed, view:{}, seqno:{}",
          node_id,
          view,
          seqno);
      }

      std::vector<uint8_t> sig_vec;
      CCF_ASSERT(
        signature_size <= sig.size(),
        fmt::format(
          "Invalid signature size, signature_size:{}, sig.size:{}",
          signature_size,
          sig.size()));
      sig_vec.assign(sig.begin(), sig.begin() + signature_size);

      auto& cert = it->second;
      BftNodeSignature bft_node_sig(std::move(sig_vec), node_id, hashed_nonce);
      try_match_unmatched_nonces(cert, bft_node_sig, view, seqno, node_id);
      cert.sigs.insert(std::pair<kv::NodeId, BftNodeSignature>(
        node_id, std::move(bft_node_sig)));

      if (can_send_sig_ack(cert, node_count))
      {
        return kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK;
      }
      return kv::TxHistory::Result::OK;
    }

    kv::TxHistory::Result record_primary(
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno,
      kv::NodeId node_id,
      crypto::Sha256Hash& root,
      Nonce& hashed_nonce,
      uint32_t node_count = 0)
    {
      auto n = entropy->random(hashed_nonce.size());
      Nonce my_nonce;
      std::copy(n.begin(), n.end(), my_nonce.begin());
      if (node_id == id)
      {
        auto h = hash_data(my_nonce);
        std::copy(h.begin(), h.end(), hashed_nonce.begin());
      }

      auto it = certificates.find(CertKey(view, seqno));
      if (it == certificates.end())
      {
        CommitCert cert(root, my_nonce);
        BftNodeSignature bft_node_sig({}, node_id, hashed_nonce);
        bft_node_sig.is_primary = true;
        try_match_unmatched_nonces(cert, bft_node_sig, view, seqno, node_id);
        cert.sigs.insert(
          std::pair<kv::NodeId, BftNodeSignature>(node_id, bft_node_sig));

        certificates.insert(
          std::pair<CertKey, CommitCert>(CertKey(view, seqno), cert));

        LOG_TRACE_FMT("Adding new root for view:{}, seqno:{}", view, seqno);
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
        try_match_unmatched_nonces(cert, bft_node_sig, view, seqno, node_id);
        cert.sigs.insert(
          std::pair<kv::NodeId, BftNodeSignature>(node_id, bft_node_sig));
        cert.my_nonce = my_nonce;
        cert.have_primary_signature = true;
        for (auto& sig : cert.sigs)
        {
          if (!verify_signature(
                sig.second.node,
                cert.root,
                sig.second.sig.size(),
                sig.second.sig.data()))
          {
            // NOTE: We need to handle this case but for now having this make a
            // test fail will be very handy
            throw ccf::ccf_logic_error(fmt::format(
              "Signature verification from {} FAILED, view:{}, seqno:{}",
              sig.first,
              view,
              seqno));
          }
          LOG_TRACE_FMT(
            "Signature verification from {} passed, view:{}, seqno:{}",
            sig.second.node,
            view,
            seqno);
        }
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

    kv::TxHistory::Result add_signature_ack(
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno,
      kv::NodeId node_id,
      uint32_t node_count = 0)
    {
      auto it = certificates.find(CertKey(view, seqno));
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r = certificates.insert(
          std::pair<CertKey, CommitCert>(CertKey(view, seqno), CommitCert()));
        it = r.first;
      }

      LOG_TRACE_FMT(
        "processing recv_signature_received_ack, from:{} view:{}, seqno:{}",
        node_id,
        view,
        seqno);

      auto& cert = it->second;
      cert.sig_acks.insert(node_id);

      if (can_send_reply_and_nonce(cert, node_count))
      {
        return kv::TxHistory::Result::SEND_REPLY_AND_NONCE;
      }
      return kv::TxHistory::Result::OK;
    }

    void add_nonce_reveal(
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno,
      Nonce nonce,
      kv::NodeId node_id)
    {
      bool did_add = false;
      auto it = certificates.find(CertKey(view, seqno));
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r = certificates.insert(
          std::pair<CertKey, CommitCert>(CertKey(view, seqno), CommitCert()));
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
        view,
        seqno,
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
          view,
          seqno,
          node_id,
          sig.hashed_nonce,
          nonce,
          hash_data(nonce),
          did_add);
        throw ccf::ccf_logic_error(fmt::format(
          "nonces do not match verification from {} FAILED, view:{}, seqno:{}",
          node_id,
          view,
          seqno));
      }
      sig.nonce = nonce;
    }

    Nonce get_my_nonce(kv::Consensus::View view, kv::Consensus::SeqNo seqno)
    {
      auto it = certificates.find(CertKey(view, seqno));
      if (it == certificates.end())
      {
        throw ccf::ccf_logic_error(fmt::format(
          "Attempting to access unknown nonce, view:{}, seqno:{}",
          view,
          seqno));
      }
      return it->second.my_nonce;
    }

    std::vector<uint8_t> get_my_hashed_nonce(
      kv::Consensus::View view, kv::Consensus::SeqNo seqno)
    {
      Nonce nonce = get_my_nonce(view, seqno);
      return hash_data(nonce);
    }

    void set_node_id(kv::NodeId id_)
    {
      id = id_;
    }

  private:
    kv::NodeId id;
    ccf::Nodes& nodes;
    std::shared_ptr<tls::Entropy> entropy;

    struct CertKey
    {
      CertKey(kv::Consensus::View view_, kv::Consensus::SeqNo seqno_) :
        view(view_),
        seqno(seqno_)
      {}

      kv::Consensus::View view;
      kv::Consensus::SeqNo seqno;

      bool operator<(const CertKey& rhs) const
      {
        if (seqno == rhs.seqno)
        {
          return view < rhs.view;
        }
        return seqno < rhs.seqno;
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
      std::map<kv::NodeId, Nonce> unmatched_nonces;
      Nonce my_nonce;
      bool have_primary_signature = false;
      bool ack_sent = false;
      bool reply_and_nonce_sent = false;
    };
    std::map<CertKey, CommitCert> certificates;

    bool verify_signature(
      kv::NodeId node_id,
      crypto::Sha256Hash& root,
      uint32_t sig_size,
      uint8_t* sig)
    {
      // TODO: Create this tx from a Store, somehow...
      kv::Tx tx;
      auto ni_tv = tx.get_view_old(nodes);

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

    std::vector<uint8_t> hash_data(Nonce data)
    {
      tls::HashBytes hash;
      tls::do_hash(
        reinterpret_cast<const uint8_t*>(&data),
        data.size(),
        hash,
        MBEDTLS_MD_SHA256);
      return hash;
    }

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
  };
}