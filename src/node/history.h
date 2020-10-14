// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "ds/dl_list.h"
#include "ds/logger.h"
#include "ds/thread_messaging.h"
#include "entities.h"
#include "kv/kv_types.h"
#include "kv/store.h"
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

  constexpr int MAX_HISTORY_LEN = 1000;

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
    kv::Store& store;
    NodeId id;
    Signatures& signatures;

  public:
    NullTxHistory(
      kv::Store& store_,
      NodeId id_,
      tls::KeyPair&,
      Signatures& signatures_,
      Nodes&) :
      store(store_),
      id(id_),
      signatures(signatures_)
    {}

    void append(const std::vector<uint8_t>&) override {}

    void append(const uint8_t*, size_t) override {}

    kv::TxHistory::Result verify_and_sign(PrimarySignature&, kv::Term*) override
    {
      return kv::TxHistory::Result::OK;
    }

    bool verify(kv::Term*, ccf::PrimarySignature*) override
    {
      return true;
    }

    void rollback(kv::Version) override {}

    void compact(kv::Version) override {}

    bool init_from_snapshot(const std::vector<uint8_t>&) override
    {
      return true;
    }

    std::vector<uint8_t> get_raw_leaf(uint64_t) override
    {
      return {};
    }

    void emit_signature() override
    {
      auto txid = store.next_txid();
      LOG_INFO_FMT("Issuing signature at {}.{}", txid.term, txid.version);
      store.commit(
        txid,
        [txid, this]() {
          auto sig = store.create_reserved_tx(txid.version);
          auto sig_view = sig.get_view(signatures);
          PrimarySignature sig_value(id, txid.version, {0});
          sig_view->put(0, sig_value);
          return sig.commit_reserved();
        },
        true);
    }

    void try_emit_signature() override
    {
      emit_signature();
    }

    bool add_request(
      kv::TxHistory::RequestID,
      CallerId,
      const std::vector<uint8_t>&,
      const std::vector<uint8_t>&,
      uint8_t) override
    {
      return true;
    }

    void add_result(
      kv::TxHistory::RequestID,
      kv::Version,
      const std::vector<uint8_t>&) override
    {}

    void add_pending(
      kv::TxHistory::RequestID,
      kv::Version,
      std::shared_ptr<std::vector<uint8_t>>) override
    {}

    void flush_pending() override {}

    virtual void add_result(
      RequestID, kv::Version, const uint8_t*, size_t) override
    {}

    void add_result(RequestID, kv::Version) override {}

    void add_response(
      kv::TxHistory::RequestID, const std::vector<uint8_t>&) override
    {}

    void register_on_result(ResultCallbackHandler) override {}

    void register_on_response(ResponseCallbackHandler) override {}

    void clear_on_result() override {}

    void clear_on_response() override {}

    crypto::Sha256Hash get_replicated_state_root() override
    {
      return crypto::Sha256Hash();
    }

    std::vector<uint8_t> get_receipt(kv::Version) override
    {
      return {};
    }

    bool verify_receipt(const std::vector<uint8_t>&) override
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

    struct Path
    {
      path* raw;

      Path()
      {
        raw = mt_init_path(crypto::Sha256Hash::SIZE);
      }

      ~Path()
      {
        mt_free_path(raw);
      }
    };

    std::shared_ptr<Path> path;

  public:
    Receipt()
    {
      path = std::make_shared<Path>();
    }

    Receipt(const std::vector<uint8_t>& v)
    {
      path = std::make_shared<Path>();
      const uint8_t* buf = v.data();
      size_t s = v.size();
      index = serialized::read<decltype(index)>(buf, s);
      max_index = serialized::read<decltype(max_index)>(buf, s);
      std::copy(buf, buf + root.h.size(), root.h.data());
      buf += root.h.size();
      s -= root.h.size();
      for (size_t i = 0; i < s; i += root.SIZE)
      {
        mt_path_insert(path->raw, const_cast<uint8_t*>(buf + i));
      }
    }

    Receipt(merkle_tree* tree, uint64_t index_)
    {
      index = index_;
      path = std::make_shared<Path>();

      if (!mt_get_path_pre(tree, index, path->raw, root.h.data()))
      {
        throw std::logic_error("Precondition to mt_get_path violated");
      }

      max_index = mt_get_path(tree, index, path->raw, root.h.data());
    }

    Receipt(const Receipt&) = delete;

    bool verify(merkle_tree* tree) const
    {
      if (!mt_verify_pre(
            tree, index, max_index, path->raw, (uint8_t*)root.h.data()))
      {
        throw std::logic_error("Precondition to mt_verify violated");
      }

      return mt_verify(
        tree, index, max_index, path->raw, (uint8_t*)root.h.data());
    }

    std::vector<uint8_t> to_v() const
    {
      size_t path_length = mt_get_path_length(path->raw);
      size_t vs = sizeof(index) + sizeof(max_index) + root.h.size() +
        (root.h.size() * path_length);
      std::vector<uint8_t> v(vs);
      uint8_t* buf = v.data();
      serialized::write(buf, vs, index);
      serialized::write(buf, vs, max_index);
      serialized::write(buf, vs, root.h.data(), root.h.size());
      for (size_t i = 0; i < path_length; ++i)
      {
        if (!mt_get_path_step_pre(path->raw, i))
          throw std::logic_error("Precondition to mt_get_path_step violated");
        uint8_t* step = mt_get_path_step(path->raw, i);
        serialized::write(buf, vs, step, root.h.size());
      }
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
      tree = mt_deserialize(
        serialised.data(), serialised.size(), mt_sha256_compress);
    }

    MerkleTreeHistory(crypto::Sha256Hash first_hash = {})
    {
      tree = mt_create(first_hash.h.data());
    }

    ~MerkleTreeHistory()
    {
      mt_free(tree);
    }

    void deserialise(const std::vector<uint8_t>& serialised)
    {
      mt_free(tree);
      tree = mt_deserialize(
        serialised.data(), serialised.size(), mt_sha256_compress);
    }

    void append(crypto::Sha256Hash& hash)
    {
      uint8_t* h = hash.h.data();
      if (!mt_insert_pre(tree, h))
      {
        throw std::logic_error("Precondition to mt_insert violated");
      }
      mt_insert(tree, h);
    }

    crypto::Sha256Hash get_root() const
    {
      crypto::Sha256Hash res;
      if (!mt_get_root_pre(tree, res.h.data()))
      {
        throw std::logic_error("Precondition to mt_get_root violated");
      }
      mt_get_root(tree, res.h.data());
      return res;
    }

    void operator=(const MerkleTreeHistory& rhs)
    {
      mt_free(tree);
      crypto::Sha256Hash root(rhs.get_root());
      tree = mt_create(root.h.data());
    }

    void flush(uint64_t index)
    {
      if (!mt_flush_to_pre(tree, index))
      {
        throw std::logic_error("Precondition to mt_flush_to violated");
      }
      LOG_TRACE_FMT("mt_flush_to index={}", index);
      mt_flush_to(tree, index);
    }

    void retract(uint64_t index)
    {
      if (!mt_retract_to_pre(tree, index))
      {
        throw std::logic_error("Precondition to mt_retract_to violated");
      }
      mt_retract_to(tree, index);
    }

    Receipt get_receipt(uint64_t index)
    {
      if (index < begin_index())
      {
        throw std::logic_error(fmt::format(
          "Cannot produce receipt for {}: index is too old and has been "
          "flushed from memory",
          index));
      }
      if (index > end_index())
      {
        throw std::logic_error(fmt::format(
          "Cannot produce receipt for {}: index is not yet known", index));
      }
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

    uint64_t begin_index()
    {
      return tree->offset + tree->i;
    }

    uint64_t end_index()
    {
      return tree->offset + tree->j - 1;
    }

    bool in_range(uint64_t index)
    {
      return index >= begin_index() && index <= end_index();
    }

    crypto::Sha256Hash get_leaf(uint64_t index)
    {
      if (!in_range(index))
      {
        throw std::logic_error("Cannot get leaf for out-of-range index");
      }

      const auto leaves = tree->hs.vs[0];

      // We flush pairs of hashes, the offset to this leaf depends on the first
      // index's parity
      const auto first_index = begin_index();
      const auto leaf_index =
        index - first_index + (first_index % 2 == 0 ? 0 : 1);

      if (leaf_index >= leaves.sz)
      {
        throw std::logic_error("Error in leaf offset calculation");
      }

      const auto leaf_data = leaves.vs[leaf_index];

      crypto::Sha256Hash leaf;
      std::memcpy(leaf.h.data(), leaf_data, leaf.h.size());
      return leaf;
    }
  };

  template <class T>
  class HashedTxHistory : public kv::TxHistory
  {
    kv::Store& store;
    NodeId id;
    T replicated_state_tree;

    tls::KeyPair& kp;
    Signatures& signatures;
    Nodes& nodes;

    std::map<RequestID, std::vector<uint8_t>> requests;
    std::map<RequestID, std::pair<kv::Version, crypto::Sha256Hash>> results;
    std::map<RequestID, std::vector<uint8_t>> responses;
    std::optional<ResultCallbackHandler> on_result;
    std::optional<ResponseCallbackHandler> on_response;

    threading::Task::TimerEntry emit_signature_timer_entry;
    size_t sig_tx_interval;
    size_t sig_ms_interval;

    void discard_pending(kv::Version v)
    {
      std::lock_guard<SpinLock> vguard(version_lock);
      auto* p = pending_inserts.get_head();
      while (p != nullptr)
      {
        auto* next = p->next;
        if (p->version > v)
        {
          pending_inserts.remove(p);
          delete p;
        }
        p = next;
      }
    }

  public:
    HashedTxHistory(
      kv::Store& store_,
      NodeId id_,
      tls::KeyPair& kp_,
      Signatures& sig_,
      Nodes& nodes_,
      size_t sig_tx_interval_ = 0,
      size_t sig_ms_interval_ = 0) :
      store(store_),
      id(id_),
      kp(kp_),
      signatures(sig_),
      nodes(nodes_),
      sig_tx_interval(sig_tx_interval_),
      sig_ms_interval(sig_ms_interval_)
    {
      start_signature_emit_timer();
    }

    void start_signature_emit_timer()
    {
      struct EmitSigMsg
      {
        EmitSigMsg(HashedTxHistory<T>* self_) : self(self_) {}
        HashedTxHistory<T>* self;
      };

      auto emit_sig_msg = std::make_unique<threading::Tmsg<EmitSigMsg>>(
        [](std::unique_ptr<threading::Tmsg<EmitSigMsg>> msg) {
          auto self = msg->data.self;

          std::unique_lock<SpinLock> mguard(
            self->signature_lock, std::defer_lock);

          const int64_t sig_ms_interval = self->sig_ms_interval;
          int64_t delta_time_to_next_sig = sig_ms_interval;

          if (mguard.try_lock())
          {
            // NOTE: time is set on every thread via a thread message
            //       time_of_last_signature is a atomic that can be set by any
            //       thread
            auto time = threading::ThreadMessaging::thread_messaging
                          .get_current_time_offset()
                          .count();
            auto time_of_last_signature = self->time_of_last_signature.count();

            auto consensus = self->store.get_consensus();
            if (
              (consensus != nullptr) && consensus->is_primary() &&
              self->store.commit_gap() > 0 && time > time_of_last_signature &&
              (time - time_of_last_signature) > sig_ms_interval)
            {
              msg->data.self->emit_signature();
            }

            delta_time_to_next_sig =
              sig_ms_interval - (time - self->time_of_last_signature.count());

            if (
              delta_time_to_next_sig <= 0 ||
              delta_time_to_next_sig > sig_ms_interval)
            {
              delta_time_to_next_sig = sig_ms_interval;
            }
          }

          self->emit_signature_timer_entry =
            threading::ThreadMessaging::thread_messaging.add_task_after(
              std::move(msg),
              std::chrono::milliseconds(delta_time_to_next_sig));
        },
        this);

      emit_signature_timer_entry =
        threading::ThreadMessaging::thread_messaging.add_task_after(
          std::move(emit_sig_msg), std::chrono::milliseconds(1000));
    }

    ~HashedTxHistory()
    {
      threading::ThreadMessaging::thread_messaging.cancel_timer_task(
        emit_signature_timer_entry);
    }

    void register_on_result(ResultCallbackHandler func) override
    {
      if (on_result.has_value())
      {
        throw std::logic_error("on_result has already been set");
      }
      on_result = func;
    }

    void register_on_response(ResponseCallbackHandler func) override
    {
      if (on_response.has_value())
      {
        throw std::logic_error("on_response has already been set");
      }
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

    bool init_from_snapshot(
      const std::vector<uint8_t>& hash_at_snapshot) override
    {
      // The history can be initialised after a snapshot has been applied by
      // deserialising the tree in the signatures table and then applying the
      // hash of the transaction at which the snapshot was taken
      auto tx = store.create_read_only_tx();
      auto sig_tv = tx.get_read_only_view(signatures);
      auto sig = sig_tv->get(0);
      if (!sig.has_value())
      {
        LOG_FAIL_FMT("No signature found in signatures map");
        return false;
      }

      CCF_ASSERT_FMT(
        !replicated_state_tree.in_range(1),
        "Tree is not empty before initialising from snapshot");

      replicated_state_tree.deserialise(sig->tree);

      crypto::Sha256Hash hash;
      std::copy_n(
        hash_at_snapshot.begin(), crypto::Sha256Hash::SIZE, hash.h.begin());
      replicated_state_tree.append(hash);
      return true;
    }

    crypto::Sha256Hash get_replicated_state_root() override
    {
      return replicated_state_tree.get_root();
    }

    void append(const std::vector<uint8_t>& replicated) override
    {
      append(replicated.data(), replicated.size());
    }

    void append(const uint8_t* replicated, size_t replicated_size) override
    {
      crypto::Sha256Hash rh({replicated, replicated_size});
      log_hash(rh, APPEND);
      replicated_state_tree.append(rh);
    }

    kv::TxHistory::Result verify_and_sign(
      PrimarySignature& sig, kv::Term* term = nullptr) override
    {
      if (!verify(term, &sig))
      {
        return kv::TxHistory::Result::FAIL;
      }

      kv::TxHistory::Result result = kv::TxHistory::Result::OK;

      auto progress_tracker = store.get_progress_tracker();
      CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
      result = progress_tracker->record_primary(
        {sig.view, sig.seqno},
        sig.node,
        sig.root,
        sig.hashed_nonce,
        store.get_consensus()->node_count());

      sig.node = id;
      sig.sig = kp.sign_hash(sig.root.h.data(), sig.root.h.size());

      return result;
    }

    bool verify(
      kv::Term* term = nullptr, PrimarySignature* signature = nullptr) override
    {
      auto tx = store.create_tx();
      auto [sig_tv, ni_tv] = tx.get_view(signatures, nodes);
      auto sig = sig_tv->get(0);
      if (!sig.has_value())
      {
        LOG_FAIL_FMT("No signature found in signatures map");
        return false;
      }
      auto& sig_value = sig.value();
      if (term)
      {
        *term = sig_value.view;
      }

      if (signature)
      {
        *signature = sig_value;
      }

      auto ni = ni_tv->get(sig_value.node);
      if (!ni.has_value())
      {
        LOG_FAIL_FMT(
          "No node info, and therefore no cert for node {}", sig_value.node);
        return false;
      }
      tls::VerifierPtr from_cert = tls::make_verifier(ni.value().cert);
      crypto::Sha256Hash root = replicated_state_tree.get_root();
      log_hash(root, VERIFY);
      bool result = from_cert->verify_hash(
        root.h.data(),
        root.h.size(),
        sig_value.sig.data(),
        sig_value.sig.size());

      if (!result)
      {
        return false;
      }

      return true;
    }

    void rollback(kv::Version v) override
    {
      discard_pending(v);
      replicated_state_tree.retract(v);
      log_hash(replicated_state_tree.get_root(), ROLLBACK);
    }

    void compact(kv::Version v) override
    {
      flush_pending();
      // Receipts can only be retrieved to the flushed index. Keep a range of
      // history so that a range of receipts are available.
      if (v > MAX_HISTORY_LEN)
      {
        replicated_state_tree.flush(v - MAX_HISTORY_LEN);
      }
      log_hash(replicated_state_tree.get_root(), COMPACT);
    }

    kv::Version last_signed_tx = 0;
    std::chrono::milliseconds time_of_last_signature =
      std::chrono::milliseconds(0);

    SpinLock signature_lock;

    void try_emit_signature() override
    {
      std::unique_lock<SpinLock> mguard(signature_lock, std::defer_lock);
      if (store.commit_gap() < sig_tx_interval || !mguard.try_lock())
      {
        return;
      }

      if (store.commit_gap() >= sig_tx_interval)
      {
        emit_signature();
      }
    }

    void emit_signature() override
    {
      // Signatures are only emitted when there is a consensus
      auto consensus = store.get_consensus();
      if (!consensus)
      {
        return;
      }

      // Signatures are only emitted when the consensus is establishing commit
      // over the node's own transactions
      auto signable_txid = consensus->get_signable_txid();
      if (!signable_txid.has_value())
      {
        return;
      }

      auto commit_txid = signable_txid.value();
      auto txid = store.next_txid();

      last_signed_tx = commit_txid.second;
      time_of_last_signature =
        threading::ThreadMessaging::thread_messaging.get_current_time_offset();

      LOG_DEBUG_FMT(
        "Signed at {} in view: {} commit was: {}.{}",
        txid.version,
        txid.term,
        commit_txid.first,
        commit_txid.second);

      store.commit(
        txid,
        [txid, commit_txid, this]() {
          auto sig = store.create_reserved_tx(txid.version);
          auto sig_view = sig.get_view(signatures);
          crypto::Sha256Hash root = replicated_state_tree.get_root();

          Nonce hashed_nonce;
          auto consensus = store.get_consensus();
          if (consensus != nullptr && consensus->type() == ConsensusType::BFT)
          {
            auto progress_tracker = store.get_progress_tracker();
            CCF_ASSERT(
              progress_tracker != nullptr, "progress_tracker is not set");
            auto r =
              progress_tracker->record_primary(txid, id, root, hashed_nonce);
            if (r != kv::TxHistory::Result::OK)
            {
              throw ccf::ccf_logic_error(fmt::format(
                "Expected success when primary added signature to the "
                "progress "
                "tracker. r:{}, view:{}, seqno:{}",
                r,
                txid.term,
                txid.version));
            }

            auto h = progress_tracker->get_my_hashed_nonce(txid);
            std::copy(h.begin(), h.end(), hashed_nonce.begin());
          }
          else
          {
            hashed_nonce.fill(0);
          }

          PrimarySignature sig_value(
            id,
            txid.version,
            txid.term,
            commit_txid.second,
            commit_txid.first,
            root,
            hashed_nonce,
            kp.sign_hash(root.h.data(), root.h.size()),
            replicated_state_tree.serialise());

          sig_view->put(0, sig_value);
          return sig.commit_reserved();
        },
        true);
    }

    std::vector<uint8_t> get_receipt(kv::Version index) override
    {
      return replicated_state_tree.get_receipt(index).to_v();
    }

    bool verify_receipt(const std::vector<uint8_t>& v) override
    {
      Receipt r(v);
      return replicated_state_tree.verify(r);
    }

    std::vector<uint8_t> get_raw_leaf(uint64_t index) override
    {
      auto leaf = replicated_state_tree.get_leaf(index);
      return {leaf.h.begin(), leaf.h.end()};
    }

    bool add_request(
      kv::TxHistory::RequestID id,
      CallerId caller_id,
      const std::vector<uint8_t>& caller_cert,
      const std::vector<uint8_t>& request,
      uint8_t frame_format) override
    {
      LOG_DEBUG_FMT("HISTORY: add_request {0}", id);
      requests[id] = request;

      auto consensus = store.get_consensus();
      if (!consensus)
      {
        return false;
      }

      return consensus->on_request(
        {id, request, caller_id, caller_cert, frame_format});
    }

    struct PendingInsert
    {
      PendingInsert(
        kv::TxHistory::RequestID i,
        kv::Version v,
        std::shared_ptr<std::vector<uint8_t>> r) :
        id(i),
        version(v),
        replicated(std::move(r)),
        next(nullptr),
        prev(nullptr)
      {}

      kv::TxHistory::RequestID id;
      kv::Version version;
      std::shared_ptr<std::vector<uint8_t>> replicated;
      PendingInsert* next;
      PendingInsert* prev;
    };

    SpinLock version_lock;
    snmalloc::DLList<PendingInsert, std::nullptr_t, true> pending_inserts;

    void add_pending(
      kv::TxHistory::RequestID id,
      kv::Version version,
      std::shared_ptr<std::vector<uint8_t>> replicated) override
    {
      add_result(id, version, replicated->data(), replicated->size());
    }

    void flush_pending() override
    {
      snmalloc::DLList<PendingInsert, std::nullptr_t, true> pi;
      {
        std::lock_guard<SpinLock> vguard(version_lock);
        pi = std::move(pending_inserts);
      }

      PendingInsert* p = pi.get_head();
      while (p != nullptr)
      {
        add_result(p->id, p->version, *p->replicated);
        p = p->next;
      }
    }

    void add_result(
      kv::TxHistory::RequestID id,
      kv::Version version,
      const std::vector<uint8_t>& replicated) override
    {
      add_result(id, version, replicated.data(), replicated.size());
    }

    void add_result(
      RequestID id,
      kv::Version version,
      const uint8_t* replicated,
      size_t replicated_size) override
    {
      append(replicated, replicated_size);

      auto consensus = store.get_consensus();

      if (consensus != nullptr && consensus->type() == ConsensusType::BFT)
      {
        if (on_result.has_value())
        {
          auto root = get_replicated_state_root();
          LOG_DEBUG_FMT("HISTORY: add_result {0} {1} {2}", id, version, root);
          results[id] = {version, root};
          on_result.value()({id, version, root});
        }
      }
    }

    void add_result(kv::TxHistory::RequestID id, kv::Version version) override
    {
      auto consensus = store.get_consensus();

      if (consensus != nullptr && consensus->type() == ConsensusType::BFT)
      {
        if (on_result.has_value())
        {
          auto root = get_replicated_state_root();
          LOG_DEBUG_FMT("HISTORY: add_result {0} {1} {2}", id, version, root);
          results[id] = {version, root};
          on_result.value()({id, version, root});
        }
      }
    }

    void add_response(
      kv::TxHistory::RequestID id,
      const std::vector<uint8_t>& response) override
    {
      LOG_DEBUG_FMT("HISTORY: add_response {0}", id);
      responses[id] = response;
    }
  };

  using MerkleTxHistory = HashedTxHistory<MerkleTreeHistory>;
}