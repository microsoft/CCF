// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"
#include "ds/ccf_exception.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "node_signature.h"
#include "nodes.h"
#include "tls/tls.h"
#include "tls/verifier.h"

#include <array>
#include <vector>

namespace ccf
{
  class ProgressTracker
  {
  public:
    ProgressTracker(kv::NodeId id_, ccf::Nodes& nodes_) : id(id_), nodes(nodes_)
    {}

    kv::TxHistory::Result add_signature(
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno,
      kv::NodeId node_id,
      uint32_t signature_size,
      std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN>& sig,
      uint64_t hashed_nonce,
      uint32_t node_count)
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
        signature_size < sig.size(),
        fmt::format(
          "Invalid signature size, signature_size:{}, sig.size:{}",
          signature_size,
          sig.size()));
      sig_vec.assign(sig.begin(), sig.begin() + signature_size);

      auto& cert = it->second;
      cert.sigs.insert(std::pair<kv::NodeId, BftNodeSignature>(
        node_id, {std::move(sig_vec), node_id, hashed_nonce}));

      auto it_unmatched_nonce = cert.unmatched_nonces.find(node_id);
      if (it_unmatched_nonce != cert.unmatched_nonces.end())
      {
        add_nonce_reveal(view, seqno, it_unmatched_nonce->second, node_id, node_count);
        cert.unmatched_nonces.erase(it_unmatched_nonce);
      }

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
      uint64_t hashed_nonce,
      uint32_t node_count = 0)
    {
      auto it = certificates.find(CertKey(view, seqno));
      if (it == certificates.end())
      {
        certificates.insert(std::pair<CertKey, CommitCert>(
          CertKey(view, seqno), CommitCert(root, hashed_nonce, node_id)));
        LOG_TRACE_FMT("Adding new root for view:{}, seqno:{}", view, seqno);
        return kv::TxHistory::Result::OK;
      }
      else
      {
        // We received some entries before we got the root so we now need to
        // verify the signatures
        auto& cert = it->second;
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

      auto it_unmatched_nonce = cert.unmatched_nonces.find(node_id);
      if (it_unmatched_nonce != cert.unmatched_nonces.end())
      {
        add_nonce_reveal(view, seqno, it_unmatched_nonce->second, node_id, node_count);
        cert.unmatched_nonces.erase(it_unmatched_nonce);
      }


      // TODO: we should be returning the possibility of sending multiple messages
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
      uint64_t nonce,
      kv::NodeId node_id,
      uint32_t /*node_count = 0*/)
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

      auto& cert = it->second;
      auto it_node_sig = cert.sigs.find(node_id);
      if (it_node_sig == cert.sigs.end())
      {
        // TODO: keep unmatched nonces separate
        cert.unmatched_nonces.insert(std::pair<kv::NodeId, uint64_t>(node_id, nonce));
        return;
      }

      BftNodeSignature& sig = it_node_sig->second;
      // TODO: we need to hash the nonce here to make sure it is correct
      sig.nonce = nonce;
    }

    void set_node_id(kv::NodeId id_)
    {
      id = id_;
    }

  private:
    kv::NodeId id;
    ccf::Nodes& nodes;

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
      uint64_t nonce;
      uint64_t hashed_nonce;
      bool is_primary;

      BftNodeSignature(
        const std::vector<uint8_t>& sig_,
        NodeId node_,
        uint64_t hashed_nonce_) :
        NodeSignature(sig_, node_), hashed_nonce(hashed_nonce_), is_primary(false)
      {}

      BftNodeSignature(NodeId node_, uint64_t hashed_nonce_) :
        NodeSignature({}, node_), hashed_nonce(hashed_nonce_), is_primary(true)
      {}
    };

    struct CommitCert
    {
      CommitCert(crypto::Sha256Hash& root_, uint64_t hashed_nonce, kv::NodeId node_id) : root(root_)
      {
        sigs.insert(std::pair<kv::NodeId, BftNodeSignature>(
          node_id, {node_id, hashed_nonce}));
      }

      CommitCert() = default;

      crypto::Sha256Hash root;
      std::map<kv::NodeId, BftNodeSignature> sigs;
      std::set<kv::NodeId> sig_acks;
      std::map<kv::NodeId, uint64_t> unmatched_nonces;
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
      kv::Tx tx;
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

    bool can_send_sig_ack(CommitCert& cert, uint32_t node_count)
    {
      // TODO: this should not be node count but 2f+1
      if(cert.sigs.size() >= node_count && !cert.ack_sent)
      {
        cert.ack_sent = true;
        return true;
      }
      return false;
    }

    bool can_send_reply_and_nonce(CommitCert& cert, uint32_t node_count)
    {
      // TODO: this should not be node count but 2f+1
      if (
        cert.sig_acks.size() >= node_count && !cert.reply_and_nonce_sent &&
        cert.ack_sent)
      {
        cert.reply_and_nonce_sent = true;
        return true;
      }
      return false;
    }
  };
}