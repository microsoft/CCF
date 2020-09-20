// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"
#include "ds/ccf_exception.h"
#include "kv/kv_types.h"

#include <array>
#include <vector>

namespace ccf
{
  class Commitment
  {
  public:
    void add_signature(
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno,
      kv::NodeId node_id,
      uint32_t signature_size,
      std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN>& sig)
    {
      auto it = certificates.find(CertKey(view, seqno));
      if (it == certificates.end())
      {
        // We currently do not know what the root is, so lets save this
        // signature and and we will verify the root when we get it from the
        // primary
        auto r = certificates.insert(
          std::pair<CertKey, Certificate>(CertKey(view, seqno), Certificate()));
        it = r.first;
      }
      else
      {
        // We need to verify the signature over the root here
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
      cert.sigs.insert(std::pair<kv::NodeId, std::vector<uint8_t>>(
        node_id, std::move(sig_vec)));
    }

    void record_primary(
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno,
      crypto::Sha256Hash& root)
    {
      auto it = certificates.find(CertKey(view, seqno));
      if (it == certificates.end())
      {
        certificates.insert(std::pair<CertKey, Certificate>(
          CertKey(view, seqno), Certificate(root)));
        return;
      }
      else
      {
        // We received some entries before we got the root so we now need to
        // verify the signatures
      }

      auto& cert = it->second;
      if (cert.root != root)
      {
        // NOTE: At this point we have cryptographic proof that someone is being
        // dishonest
        //       we need to work out what to do.
        throw ccf::ccf_logic_error("We have proof someone is being dishonest");
      }
    }

    void set_node_id(kv::NodeId id_)
    {
      id = id_;
    }

  private:
    kv::NodeId id;

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

    struct Certificate
    {
      Certificate(crypto::Sha256Hash& root_) : root(root_) {}
      Certificate() = default;

      crypto::Sha256Hash root;
      std::map<kv::NodeId, std::vector<uint8_t>> sigs;
    };

    std::map<CertKey, Certificate> certificates;
  };
}