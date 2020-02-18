// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/pbft/pbfttypes.h"
#include "crypto/hash.h"
#include "ds/logger.h"
#include "entities.h"
#include "kv/kvtypes.h"
#include "nodes.h"
#include "signatures.h"
#include "tls/tls.h"
#include "tls/verifier.h"

#include <array>
#include <deque>
#include <string.h>

extern "C"
{
#include <evercrypt/MerkleTree.h>
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

    void append(
      const std::vector<uint8_t>& replicated,
      const std::vector<uint8_t>& all_data) override
    {}

    void append(
      const uint8_t* replicated,
      size_t replicated_size,
      const uint8_t* all_data,
      size_t all_data_size) override
    {}

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
      const std::vector<uint8_t>& caller_cert,
      const std::vector<uint8_t>& request) override
    {
      return true;
    }

    void add_result(
      kv::TxHistory::RequestID id,
      kv::Version version,
      const std::vector<uint8_t>& replicated,
      const std::vector<uint8_t>& all_data) override
    {}

    virtual void add_result(
      RequestID id,
      kv::Version version,
      const uint8_t* replicated,
      size_t replicated_size,
      const uint8_t* all_data,
      size_t all_data_size) override
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

    crypto::Sha256Hash get_full_state_root() override
    {
      return crypto::Sha256Hash();
    }

    crypto::Sha256Hash get_replicated_state_root() override
    {
      return crypto::Sha256Hash();
    }

    std::vector<uint8_t> get_receipt(kv::Version v) override
    {
      return {};
    }

    bool verify_receipt(const std::vector<uint8_t>& v) override
    {
      return true;
    }
  };

  class Receipt
  {
  private:
    uint64_t index;
    uint32_t max_index;
    crypto::Sha256Hash root;
    hash_vec* path;

  public:
    Receipt()
    {
      path = init_path();
    }

    static Receipt from_v(const std::vector<uint8_t>& v)
    {
      Receipt r;
      const uint8_t* buf = v.data();
      size_t s = v.size();
      r.index = serialized::read<decltype(index)>(buf, s);
      r.max_index = serialized::read<decltype(max_index)>(buf, s);
      std::copy(buf, buf + r.root.SIZE, r.root.h);
      buf += r.root.SIZE;
      s -= r.root.SIZE;
      for (size_t i = 0; i < s; i += r.root.SIZE)
        path_insert(r.path, const_cast<uint8_t*>(buf + i));
      return r;
    }

    Receipt(merkle_tree* tree, uint64_t index_)
    {
      index = index_;
      path = init_path();

      if (!mt_get_path_pre(tree, index, path, root.h))
      {
        free_path(path);
        throw std::logic_error("Precondition to mt_get_path violated");
      }

      max_index = mt_get_path(tree, index, path, root.h);
    }

    bool verify(merkle_tree* tree) const
    {
      if (!mt_verify_pre(tree, index, max_index, path, (uint8_t*)root.h))
        throw std::logic_error("Precondition to mt_verify violated");

      return mt_verify(tree, index, max_index, path, (uint8_t*)root.h);
    }

    ~Receipt()
    {
      free_path(path);
    }

    std::vector<uint8_t> to_v() const
    {
      size_t vs =
        sizeof(index) + sizeof(max_index) + root.SIZE + root.SIZE * path->sz;
      std::vector<uint8_t> v(vs);
      uint8_t* buf = v.data();
      serialized::write(buf, vs, index);
      serialized::write(buf, vs, max_index);
      serialized::write(buf, vs, root.h, root.SIZE);
      for (size_t i = 0; i < path->sz; ++i)
        serialized::write(buf, vs, *(path->vs + i), root.SIZE);
      return v;
    }
  };

  class MerkleTreeHistory
  {
    merkle_tree* tree;

  public:
    MerkleTreeHistory(MerkleTreeHistory const&) = delete;

    MerkleTreeHistory(const std::vector<uint8_t>& serialised)
    {
      tree = mt_deserialize(serialised.data(), serialised.size());
    }

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
      LOG_TRACE_FMT("mt_flush_to index={}", index);
      mt_flush_to(tree, index);
    }

    void retract(uint64_t index)
    {
      if (!mt_retract_to_pre(tree, index))
        throw std::logic_error("Precondition to mt_retract_to violated");
      mt_retract_to(tree, index);
    }

    Receipt get_receipt(uint64_t index)
    {
      return Receipt(tree, index);
    }

    bool verify(const Receipt& r)
    {
      return r.verify(tree);
    }

    std::vector<uint8_t> serialise()
    {
      LOG_TRACE_FMT("mt_serialize_size {}", mt_serialize_size(tree));
      std::vector<uint8_t> output(mt_serialize_size(tree));
      mt_serialize(tree, output.data(), output.capacity());
      return output;
    }
  };

  template <class T>
  class HashedTxHistory : public kv::TxHistory
  {
    Store& store;
    NodeId id;
    T full_state_tree;
    T replicated_state_tree;

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

    bool is_replicated_tree_enabled()
    {
      auto consensus = store.get_consensus();
      if (!consensus || consensus->type() == ConsensusType::Pbft)
      {
        return true;
      }
      return false;
    }

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

    crypto::Sha256Hash get_full_state_root() override
    {
      return full_state_tree.get_root();
    }

    crypto::Sha256Hash get_replicated_state_root() override
    {
      return replicated_state_tree.get_root();
    }

    void append(
      const std::vector<uint8_t>& replicated,
      const std::vector<uint8_t>& all_data) override
    {
      append(
        replicated.data(), replicated.size(), all_data.data(), all_data.size());
    }

    void append(
      const uint8_t* replicated,
      size_t replicated_size,
      const uint8_t* all_data,
      size_t all_data_size) override
    {
      crypto::Sha256Hash h({{all_data, all_data_size}});
      log_hash(h, APPEND);
      full_state_tree.append(h);

      if (is_replicated_tree_enabled())
      {
        crypto::Sha256Hash rh({{replicated, replicated_size}});
        log_hash(rh, APPEND);
        replicated_state_tree.append(rh);
      }
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
      crypto::Sha256Hash root = full_state_tree.get_root();
      log_hash(root, VERIFY);
      return from_cert->verify_hash(
        root.h, root.SIZE, sig_value.sig.data(), sig_value.sig.size());
    }

    void rollback(kv::Version v) override
    {
      full_state_tree.retract(v);
      log_hash(full_state_tree.get_root(), ROLLBACK);

      if (is_replicated_tree_enabled())
      {
        replicated_state_tree.retract(v);
        log_hash(replicated_state_tree.get_root(), ROLLBACK);
      }
    }

    void compact(kv::Version v) override
    {
      if (v > MAX_HISTORY_LEN)
        full_state_tree.flush(v - MAX_HISTORY_LEN);
      log_hash(full_state_tree.get_root(), COMPACT);

      if (is_replicated_tree_enabled())
      {
        if (v > MAX_HISTORY_LEN)
          replicated_state_tree.flush(v - MAX_HISTORY_LEN);
        log_hash(replicated_state_tree.get_root(), COMPACT);
      }
    }

    void emit_signature() override
    {
#ifndef PBFT
      // Signatures are only emitted when there is a consensus
      auto consensus = store.get_consensus();
      if (!consensus)
      {
        return;
      }

      auto version = store.next_version();
      auto view = consensus->get_view();
      auto commit = consensus->get_commit_seqno();
      LOG_DEBUG_FMT("Issuing signature at {}", version);
      LOG_DEBUG_FMT("Signed at {} view: {} commit: {}", version, view, commit);
      store.commit(
        version,
        [version, view, commit, this]() {
          Store::Tx sig(version);
          auto sig_view = sig.get_view(signatures);
          crypto::Sha256Hash root = full_state_tree.get_root();
          Signature sig_value(
            id,
            version,
            view,
            commit,
            kp.sign_hash(root.h, root.SIZE),
            full_state_tree.serialise());
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
      const std::vector<uint8_t>& caller_cert,
      const std::vector<uint8_t>& request) override
    {
      LOG_DEBUG_FMT("HISTORY: add_request {0}", id);
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
      const std::vector<uint8_t>& replicated,
      const std::vector<uint8_t>& all_data) override
    {
      add_result(
        id,
        version,
        replicated.data(),
        replicated.size(),
        all_data.data(),
        all_data.size());
    }

    void add_result(
      RequestID id,
      kv::Version version,
      const uint8_t* replicated,
      size_t replicated_size,
      const uint8_t* all_data,
      size_t all_data_size) override
    {
      append(replicated, replicated_size, all_data, all_data_size);
#ifdef PBFT
      if (on_result.has_value())
      {
        auto root = get_full_state_root();
        auto replicated_root = get_replicated_state_root();
        LOG_DEBUG_FMT("HISTORY: add_result {0} {1} {2}", id, version, root);
        results[id] = {version, root};
        on_result.value()({id, version, root, replicated_root});
      }
#endif
    }

    void add_result(kv::TxHistory::RequestID id, kv::Version version) override
    {
#ifdef PBFT
      if (on_result.has_value())
      {
        auto root = get_full_state_root();
        auto replicated_root = get_replicated_state_root();
        LOG_DEBUG_FMT("HISTORY: add_result {0} {1} {2}", id, version, root);
        results[id] = {version, root};
        on_result.value()({id, version, root, replicated_root});
      }
#endif
    }

    void add_response(
      kv::TxHistory::RequestID id,
      const std::vector<uint8_t>& response) override
    {
      LOG_DEBUG_FMT("HISTORY: add_response {0}", id);
      responses[id] = response;
    }

    std::vector<uint8_t> get_receipt(kv::Version index) override
    {
      return full_state_tree.get_receipt(index).to_v();
    }

    bool verify_receipt(const std::vector<uint8_t>& v) override
    {
      auto r = Receipt::from_v(v);
      return full_state_tree.verify(r);
    }
  };

  using MerkleTxHistory = HashedTxHistory<MerkleTreeHistory>;
}