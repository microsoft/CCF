// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../consensus/pbft/pbfttypes.h"
#include "../crypto/hash.h"
#include "../ds/logger.h"
#include "../kv/kvtypes.h"
#include "../tls/keypair.h"
#include "../tls/tls.h"
#include "entities.h"
#include "nodes.h"
#include "signatures.h"

#include <array>
#include <deque>
#include <string.h>

extern "C"
{
#if defined(INSIDE_ENCLAVE) && !defined(__linux__)
// Tricks Kremlin into including the right endian.h for the enclave.
// MUSL doesn't provide any macros that it could be identified by,
// so we use our own. This avoids macro redefinition warnings.
#  define __linux__
#  include <evercrypt/MerkleTree.h>

#  undef __linux__
#else
#  include <evercrypt/MerkleTree.h>

#endif
}

namespace fmt
{
  template <>
  struct formatter<kv::TxHistory::RequestID>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const kv::TxHistory::RequestID& p, FormatContext& ctx)
    {
      return format_to(
        ctx.out(),
        "<RID {0}, {1}, {2}>",
        std::get<0>(p),
        std::get<1>(p),
        std::get<2>(p));
    }
  };
}

namespace ccf
{
  enum HashOp
  {
    APPEND,
    VERIFY,
    ROLLBACK,
    COMPACT
  };

  constexpr size_t MAX_HISTORY_LEN = 1000;

  static std::ostream& operator<<(std::ostream& os, HashOp flag)
  {
    switch (flag)
    {
      case APPEND:
        os << "append";
        break;

      case VERIFY:
        os << "verify";
        break;

      case ROLLBACK:
        os << "rollback";
        break;

      case COMPACT:
        os << "compact";
        break;
    }

    return os;
  }

  static void log_hash(const crypto::Sha256Hash& h, HashOp flag)
  {
    LOG_DEBUG_FMT("History [{}] {}", flag, h);
  }

  class NullTxHistory : public kv::TxHistory
  {
    Store& store;
    NodeId id;
    Signatures& signatures;

  public:
    NullTxHistory(
      Store& store_,
      NodeId id_,
      tls::KeyPair&,
      Signatures& signatures_,
      Nodes&) :
      store(store_),
      id(id_),
      signatures(signatures_)
    {}

    void append(const std::vector<uint8_t>&) override {}

    bool verify(kv::Term* term = nullptr) override
    {
      return true;
    }

    void rollback(kv::Version v) override {}

    void compact(kv::Version v) override {}

    void emit_signature() override
    {
      auto version = store.next_version();
      LOG_INFO_FMT("Issuing signature at {}", version);
      store.commit(
        version,
        [version, this]() {
          Store::Tx sig(version);
          auto sig_view = sig.get_view(signatures);
          Signature sig_value(id, version);
          sig_view->put(0, sig_value);
          return sig.commit_reserved();
        },
        true);
    }

    bool add_request(
      kv::TxHistory::RequestID id,
      uint64_t actor,
      CallerId caller_id,
      CBuffer& caller_cert,
      const std::vector<uint8_t>& request) override
    {
      return true;
    }
    void add_result(
      kv::TxHistory::RequestID id,
      kv::Version version,
      const std::vector<uint8_t>& data) override
    {}
    void add_result(RequestID id, kv::Version version) override {}
    void add_response(
      kv::TxHistory::RequestID id,
      const std::vector<uint8_t>& response) override
    {}

    void register_on_result(ResultCallbackHandler func) override {}

    void register_on_response(ResponseCallbackHandler func) override {}

    void clear_on_result() override {}

    void clear_on_response() override {}

    crypto::Sha256Hash get_root() override
    {
      return crypto::Sha256Hash();
    }
  };

  class MerkleTreeHistory
  {
    merkle_tree* tree;

  public:
    MerkleTreeHistory(MerkleTreeHistory const&) = delete;

    MerkleTreeHistory()
    {
      ::hash ih(init_hash());
      tree = mt_create(ih);
      free_hash(ih);
    }

    ~MerkleTreeHistory()
    {
      mt_free(tree);
    }

    void append(const crypto::Sha256Hash& hash)
    {
      uint8_t* h = const_cast<uint8_t*>(hash.h);
      if (!mt_insert_pre(tree, h))
        throw std::logic_error("Precondition to mt_insert violated");
      mt_insert(tree, h);
    }

    crypto::Sha256Hash get_root() const
    {
      crypto::Sha256Hash res;
      if (!mt_get_root_pre(tree, res.h))
        throw std::logic_error("Precondition to mt_get_root violated");
      mt_get_root(tree, res.h);
      return res;
    }

    void operator=(const MerkleTreeHistory& rhs)
    {
      mt_free(tree);
      crypto::Sha256Hash root(rhs.get_root());
      tree = mt_create(root.h);
    }

    void flush(uint64_t index)
    {
      if (!mt_flush_to_pre(tree, index))
        throw std::logic_error("Precondition to mt_flush_to violated");
      mt_flush_to(tree, index);
    }

    void retract(uint64_t index)
    {
      if (!mt_retract_to_pre(tree, index))
        throw std::logic_error("Precondition to mt_retract_to violated");
      mt_retract_to(tree, index);
    }
  };

  template <class T>
  class HashedTxHistory : public kv::TxHistory
  {
    Store& store;
    NodeId id;
    T tree;

    tls::KeyPair& kp;
    Signatures& signatures;
    Nodes& nodes;

    std::shared_ptr<kv::Consensus> consensus;

    std::map<RequestID, std::vector<uint8_t>> requests;
    std::map<RequestID, std::pair<kv::Version, crypto::Sha256Hash>> results;
    std::map<RequestID, std::vector<uint8_t>> responses;
    std::optional<ResultCallbackHandler> on_result;
    std::optional<ResponseCallbackHandler> on_response;

  public:
    HashedTxHistory(
      Store& store_,
      NodeId id_,
      tls::KeyPair& kp_,
      Signatures& sig_,
      Nodes& nodes_) :
      store(store_),
      id(id_),
      kp(kp_),
      signatures(sig_),
      nodes(nodes_)
    {}

    void register_on_result(ResultCallbackHandler func) override
    {
      if (on_result.has_value())
        throw std::logic_error("on_result has already been set");
      on_result = func;
    }

    void register_on_response(ResponseCallbackHandler func) override
    {
      if (on_response.has_value())
        throw std::logic_error("on_response has already been set");
      on_response = func;
    }

    void clear_on_result() override
    {
      on_result.reset();
    }

    void clear_on_response() override
    {
      on_response.reset();
    }

    void set_node_id(NodeId id_)
    {
      id = id_;
    }

    crypto::Sha256Hash get_root() override
    {
      return tree.get_root();
    }

    void append(const std::vector<uint8_t>& data) override
    {
      crypto::Sha256Hash h({data});
      log_hash(h, APPEND);
      tree.append(h);
    }

    bool verify(kv::Term* term = nullptr) override
    {
      Store::Tx tx;
      auto [sig_tv, ni_tv] = tx.get_view(signatures, nodes);
      auto sig = sig_tv->get(0);
      if (!sig.has_value())
      {
        LOG_FAIL_FMT("No signature found in signatures map");
        return false;
      }
      auto sig_value = sig.value();
      if (term)
        *term = sig_value.term;

      auto ni = ni_tv->get(sig_value.node);
      if (!ni.has_value())
      {
        LOG_FAIL_FMT(
          "No node info, and therefore no cert for node {}", sig_value.node);
        return false;
      }
      tls::VerifierPtr from_cert = tls::make_verifier(ni.value().cert);
      crypto::Sha256Hash root = tree.get_root();
      log_hash(root, VERIFY);
      return from_cert->verify_hash(
        root.h, root.SIZE, sig_value.sig.data(), sig_value.sig.size());
    }

    void rollback(kv::Version v) override
    {
      tree.retract(v);
      log_hash(tree.get_root(), ROLLBACK);
    }

    void compact(kv::Version v) override
    {
      if (v > MAX_HISTORY_LEN)
        tree.flush(v - MAX_HISTORY_LEN);
      log_hash(tree.get_root(), COMPACT);
    }

    void emit_signature() override
    {
#ifndef PBFT
      // Signatures are only emitted when Raft is used as consensus
      auto consensus = store.get_consensus();
      if (!consensus)
        return;

      auto version = store.next_version();
      auto view = consensus->get_view();
      auto commit = consensus->get_commit_seqno();
      LOG_INFO_FMT("Issuing signature at {}", version);
      LOG_DEBUG_FMT("Signed at {} view: {} commit: {}", version, view, commit);
      store.commit(
        version,
        [version, view, commit, this]() {
          Store::Tx sig(version);
          auto sig_view = sig.get_view(signatures);
          crypto::Sha256Hash root = tree.get_root();
          Signature sig_value(
            id, version, view, commit, kp.sign_hash(root.h, root.SIZE));
          sig_view->put(0, sig_value);
          return sig.commit_reserved();
        },
        true);
#endif
    }

    bool add_request(
      kv::TxHistory::RequestID id,
      uint64_t actor,
      CallerId caller_id,
      CBuffer& caller_cert,
      const std::vector<uint8_t>& request) override
    {
      LOG_DEBUG << fmt::format("HISTORY: add_request {0}", id) << std::endl;
      requests[id] = request;

      auto consensus = store.get_consensus();
      if (!consensus)
        return false;

      return consensus->on_request(
        {id, request, actor, caller_id, caller_cert});
    }

    void add_result(
      kv::TxHistory::RequestID id,
      kv::Version version,
      const std::vector<uint8_t>& data) override
    {
      append(data);
      auto root = get_root();
      LOG_DEBUG << fmt::format(
                     "HISTORY: add_result {0} {1} {2}", id, version, root)
                << std::endl;
#ifdef PBFT
      results[id] = {version, root};
      if (on_result.has_value())
        on_result.value()({id, version, root});
#endif
    }

    void add_result(kv::TxHistory::RequestID id, kv::Version version) override
    {
      auto root = get_root();
      LOG_DEBUG << fmt::format(
                     "HISTORY: add_result {0} {1} {2}", id, version, root)
                << std::endl;
#ifdef PBFT
      results[id] = {version, root};
      if (on_result.has_value())
        on_result.value()({id, version, root});
#endif
    }

    void add_response(
      kv::TxHistory::RequestID id,
      const std::vector<uint8_t>& response) override
    {
      LOG_DEBUG << fmt::format("HISTORY: add_response {0}", id) << std::endl;
      responses[id] = response;
    }
  };

  using MerkleTxHistory = HashedTxHistory<MerkleTreeHistory>;
}