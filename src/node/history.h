// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/pal/locking.h"
#include "ccf/service/tables/nodes.h"
#include "ds/dl_list.h"
#include "ds/thread_messaging.h"
#include "endian.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "node_signature_verify.h"
#include "service/tables/signatures.h"

#include <array>
#include <deque>
#include <string.h>

#define HAVE_OPENSSL
// merklecpp traces are off by default, even when CCF tracing is enabled
// #include "merklecpp_trace.h"
#include <merklecpp/merklecpp.h>

FMT_BEGIN_NAMESPACE
template <>
struct formatter<kv::TxHistory::RequestID>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const kv::TxHistory::RequestID& p, FormatContext& ctx) const
  {
    return format_to(
      ctx.out(), "<RID {0}, {1}>", std::get<0>(p), std::get<1>(p));
  }
};
FMT_END_NAMESPACE

namespace ccf
{
  enum HashOp
  {
    APPEND,
    VERIFY,
    ROLLBACK,
    COMPACT
  };

#ifdef OVERRIDE_MAX_HISTORY_LEN
  constexpr int MAX_HISTORY_LEN = OVERRIDE_MAX_HISTORY_LEN;
#else
  constexpr int MAX_HISTORY_LEN = 0;
#endif

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

  static inline void log_hash(const crypto::Sha256Hash& h, HashOp flag)
  {
    LOG_TRACE_FMT("History [{}] {}", flag, h);
  }

  class NullTxHistoryPendingTx : public kv::PendingTx
  {
    kv::TxID txid;
    kv::Store& store;
    NodeId id;

  public:
    NullTxHistoryPendingTx(
      kv::TxID txid_, kv::Store& store_, const NodeId& id_) :
      txid(txid_),
      store(store_),
      id(id_)
    {}

    kv::PendingTxInfo call() override
    {
      auto sig = store.create_reserved_tx(txid);
      auto signatures =
        sig.template rw<ccf::Signatures>(ccf::Tables::SIGNATURES);
      auto serialised_tree = sig.template rw<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      PrimarySignature sig_value(id, txid.version);
      signatures->put(sig_value);
      serialised_tree->put({});
      return sig.commit_reserved();
    }
  };

  class NullTxHistory : public kv::TxHistory
  {
    kv::Store& store;
    NodeId id;

  protected:
    kv::Version version = 0;
    kv::Term term_of_last_version = 0;
    kv::Term term_of_next_version = 0;

  public:
    NullTxHistory(kv::Store& store_, const NodeId& id_, crypto::KeyPair&) :
      store(store_),
      id(id_)
    {}

    void append(const std::vector<uint8_t>&) override
    {
      version++;
    }

    void append_entry(const crypto::Sha256Hash& digest) override
    {
      version++;
    }

    kv::TxHistory::Result verify_and_sign(
      PrimarySignature&, kv::Term*, kv::Configuration::Nodes&) override
    {
      return kv::TxHistory::Result::OK;
    }

    bool verify(kv::Term*, ccf::PrimarySignature*) override
    {
      return true;
    }

    void set_term(kv::Term t) override
    {
      term_of_last_version = t;
      term_of_next_version = t;
    }

    void rollback(const kv::TxID& tx_id, kv::Term commit_term_) override
    {
      version = tx_id.version;
      term_of_last_version = tx_id.term;
      term_of_next_version = commit_term_;
    }

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
      LOG_DEBUG_FMT("Issuing signature at {}.{}", txid.term, txid.version);
      store.commit(
        txid, std::make_unique<NullTxHistoryPendingTx>(txid, store, id), true);
    }

    void try_emit_signature() override {}

    void start_signature_emit_timer() override {}

    crypto::Sha256Hash get_replicated_state_root() override
    {
      return crypto::Sha256Hash(std::to_string(version));
    }

    std::tuple<kv::TxID, crypto::Sha256Hash, kv::Term>
    get_replicated_state_txid_and_root() override
    {
      return {
        {term_of_last_version, version},
        crypto::Sha256Hash(std::to_string(version)),
        term_of_next_version};
    }

    std::vector<uint8_t> get_proof(kv::Version) override
    {
      return {};
    }

    bool verify_proof(const std::vector<uint8_t>&) override
    {
      return true;
    }

    std::vector<uint8_t> serialise_tree(size_t, size_t) override
    {
      return {};
    }

    void set_endorsed_certificate(const crypto::Pem& cert) override {}
  };

  using HistoryTree = merkle::TreeT<32, merkle::sha256_openssl>;

  class Proof
  {
  private:
    HistoryTree::Hash root;
    std::shared_ptr<HistoryTree::Path> path = nullptr;

  public:
    Proof() {}

    Proof(const std::vector<uint8_t>& v)
    {
      size_t position = 0;
      root.deserialise(v, position);
      path = std::make_shared<HistoryTree::Path>(v, position);
    }

    const HistoryTree::Hash& get_root() const
    {
      return root;
    }

    std::shared_ptr<HistoryTree::Path> get_path()
    {
      return path;
    }

    Proof(HistoryTree* tree, uint64_t index)
    {
      root = tree->root();
      path = tree->path(index);
    }

    Proof(const Proof&) = delete;

    bool verify(HistoryTree* tree) const
    {
      if (path->max_index() > tree->max_index())
      {
        return false;
      }
      else if (tree->max_index() == path->max_index())
      {
        return tree->root() == root && path->verify(root);
      }
      else
      {
        auto past_root = tree->past_root(path->max_index());
        return path->verify(*past_root);
      }
    }

    std::vector<uint8_t> to_v() const
    {
      std::vector<uint8_t> v;
      root.serialise(v);
      path->serialise(v);
      return v;
    }
  };

  template <class T>
  class MerkleTreeHistoryPendingTx : public kv::PendingTx
  {
    kv::TxID txid;
    ccf::SeqNo previous_signature_seqno;
    kv::Store& store;
    kv::TxHistory& history;
    NodeId id;
    crypto::KeyPair& kp;
    crypto::Pem& endorsed_cert;

  public:
    MerkleTreeHistoryPendingTx(
      kv::TxID txid_,
      ccf::SeqNo previous_signature_seqno_,
      kv::Store& store_,
      kv::TxHistory& history_,
      const NodeId& id_,
      crypto::KeyPair& kp_,
      crypto::Pem& endorsed_cert_) :
      txid(txid_),
      previous_signature_seqno(previous_signature_seqno_),
      store(store_),
      history(history_),
      id(id_),
      kp(kp_),
      endorsed_cert(endorsed_cert_)
    {}

    kv::PendingTxInfo call() override
    {
      auto sig = store.create_reserved_tx(txid);
      auto signatures =
        sig.template rw<ccf::Signatures>(ccf::Tables::SIGNATURES);
      auto serialised_tree = sig.template rw<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      crypto::Sha256Hash root = history.get_replicated_state_root();

      std::vector<uint8_t> primary_sig;
      auto consensus = store.get_consensus();

      primary_sig = kp.sign_hash(root.h.data(), root.h.size());

      PrimarySignature sig_value(
        id,
        txid.version,
        txid.term,
        root,
        {}, // Nonce is currently empty
        primary_sig,
        endorsed_cert);

      signatures->put(sig_value);
      serialised_tree->put(
        history.serialise_tree(previous_signature_seqno, txid.version - 1));
      return sig.commit_reserved();
    }
  };

  class MerkleTreeHistory
  {
    HistoryTree* tree;

  public:
    MerkleTreeHistory(MerkleTreeHistory const&) = delete;

    MerkleTreeHistory(const std::vector<uint8_t>& serialised)
    {
      tree = new HistoryTree(serialised);
    }

    MerkleTreeHistory(crypto::Sha256Hash first_hash = {})
    {
      tree = new HistoryTree(merkle::Hash(first_hash.h));
    }

    ~MerkleTreeHistory()
    {
      delete (tree);
      tree = nullptr;
    }

    void deserialise(const std::vector<uint8_t>& serialised)
    {
      delete (tree);
      tree = new HistoryTree(serialised);
    }

    void append(const crypto::Sha256Hash& hash)
    {
      tree->insert(merkle::Hash(hash.h));
    }

    crypto::Sha256Hash get_root() const
    {
      const merkle::Hash& root = tree->root();
      crypto::Sha256Hash result;
      std::copy(root.bytes, root.bytes + root.size(), result.h.begin());
      return result;
    }

    void operator=(const MerkleTreeHistory& rhs)
    {
      delete (tree);
      crypto::Sha256Hash root(rhs.get_root());
      tree = new HistoryTree(merkle::Hash(root.h));
    }

    void flush(uint64_t index)
    {
      LOG_TRACE_FMT("mt_flush_to index={}", index);
      tree->flush_to(index);
    }

    void retract(uint64_t index)
    {
      LOG_TRACE_FMT("mt_retract_to index={}", index);
      tree->retract_to(index);
    }

    Proof get_proof(uint64_t index)
    {
      if (index < begin_index())
      {
        throw std::logic_error(fmt::format(
          "Cannot produce proof for {}: index is too old and has been "
          "flushed from memory",
          index));
      }
      if (index > end_index())
      {
        throw std::logic_error(fmt::format(
          "Cannot produce proof for {}: index is not yet known", index));
      }
      return Proof(tree, index);
    }

    bool verify(const Proof& r)
    {
      return r.verify(tree);
    }

    std::vector<uint8_t> serialise()
    {
      LOG_TRACE_FMT("mt_serialize_size {}", tree->serialised_size());
      std::vector<uint8_t> output;
      tree->serialise(output);
      return output;
    }

    std::vector<uint8_t> serialise(size_t from, size_t to)
    {
      LOG_TRACE_FMT(
        "mt_serialize_size ({},{}) {}",
        from,
        to,
        tree->serialised_size(from, to));
      std::vector<uint8_t> output;
      tree->serialise(from, to, output);
      return output;
    }

    uint64_t begin_index()
    {
      return tree->min_index();
    }

    uint64_t end_index()
    {
      return tree->max_index();
    }

    bool in_range(uint64_t index)
    {
      return index >= begin_index() && index <= end_index();
    }

    crypto::Sha256Hash get_leaf(uint64_t index)
    {
      const merkle::Hash& leaf = tree->leaf(index);
      crypto::Sha256Hash result;
      std::copy(leaf.bytes, leaf.bytes + leaf.size(), result.h.begin());
      return result;
    }
  };

  template <class T>
  class HashedTxHistory : public kv::TxHistory
  {
    kv::Store& store;
    NodeId id;
    T replicated_state_tree;

    crypto::KeyPair& kp;

    threading::Task::TimerEntry emit_signature_timer_entry;
    size_t sig_tx_interval;
    size_t sig_ms_interval;

    ccf::pal::Mutex state_lock;
    kv::Term term_of_last_version = 0;
    kv::Term term_of_next_version;

    std::optional<crypto::Pem> endorsed_cert = std::nullopt;

  public:
    HashedTxHistory(
      kv::Store& store_,
      const NodeId& id_,
      crypto::KeyPair& kp_,
      size_t sig_tx_interval_ = 0,
      size_t sig_ms_interval_ = 0,
      bool signature_timer = false) :
      store(store_),
      id(id_),
      kp(kp_),
      sig_tx_interval(sig_tx_interval_),
      sig_ms_interval(sig_ms_interval_)
    {
      if (signature_timer)
      {
        start_signature_emit_timer();
      }
    }

    void start_signature_emit_timer() override
    {
      struct EmitSigMsg
      {
        EmitSigMsg(HashedTxHistory<T>* self_) : self(self_) {}
        HashedTxHistory<T>* self;
      };

      auto emit_sig_msg = std::make_unique<threading::Tmsg<EmitSigMsg>>(
        [](std::unique_ptr<threading::Tmsg<EmitSigMsg>> msg) {
          auto self = msg->data.self;

          std::unique_lock<ccf::pal::Mutex> mguard(
            self->signature_lock, std::defer_lock);

          bool should_emit_signature = false;

          if (mguard.try_lock())
          {
            auto consensus = self->store.get_consensus();
            if (consensus != nullptr)
            {
              auto sig_disp = consensus->get_signature_disposition();
              switch (sig_disp)
              {
                case kv::Consensus::SignatureDisposition::CANT_REPLICATE:
                {
                  break;
                }
                case kv::Consensus::SignatureDisposition::CAN_SIGN:
                {
                  if (self->store.committable_gap() > 0)
                  {
                    should_emit_signature = true;
                  }
                  break;
                }
                case kv::Consensus::SignatureDisposition::SHOULD_SIGN:
                {
                  should_emit_signature = true;
                  break;
                }
              }
            }
          }

          if (should_emit_signature)
          {
            msg->data.self->emit_signature();
          }

          self->emit_signature_timer_entry =
            threading::ThreadMessaging::thread_messaging.add_task_after(
              std::move(msg), std::chrono::milliseconds(self->sig_ms_interval));
        },
        this);

      emit_signature_timer_entry =
        threading::ThreadMessaging::thread_messaging.add_task_after(
          std::move(emit_sig_msg), std::chrono::milliseconds(sig_ms_interval));
    }

    ~HashedTxHistory()
    {
      threading::ThreadMessaging::thread_messaging.cancel_timer_task(
        emit_signature_timer_entry);
    }

    void set_node_id(const NodeId& id_)
    {
      id = id_;
    }

    bool init_from_snapshot(
      const std::vector<uint8_t>& hash_at_snapshot) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      // The history can be initialised after a snapshot has been applied by
      // deserialising the tree in the signatures table and then applying the
      // hash of the transaction at which the snapshot was taken
      auto tx = store.create_read_only_tx();
      auto tree_h = tx.template ro<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      auto tree = tree_h->get();
      if (!tree.has_value())
      {
        LOG_FAIL_FMT("No tree found in serialised tree map");
        return false;
      }

      CCF_ASSERT_FMT(
        !replicated_state_tree.in_range(1),
        "Tree is not empty before initialising from snapshot");

      replicated_state_tree.deserialise(tree.value());

      crypto::Sha256Hash hash;
      std::copy_n(
        hash_at_snapshot.begin(), crypto::Sha256Hash::SIZE, hash.h.begin());
      replicated_state_tree.append(hash);
      return true;
    }

    crypto::Sha256Hash get_replicated_state_root() override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      return replicated_state_tree.get_root();
    }

    std::tuple<kv::TxID, crypto::Sha256Hash, kv::Term>
    get_replicated_state_txid_and_root() override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      return {
        {term_of_last_version,
         static_cast<kv::Version>(replicated_state_tree.end_index())},
        replicated_state_tree.get_root(),
        term_of_next_version};
    }

    kv::TxHistory::Result verify_and_sign(
      PrimarySignature& sig,
      kv::Term* term,
      kv::Configuration::Nodes& config) override
    {
      if (!verify(term, &sig))
      {
        return kv::TxHistory::Result::FAIL;
      }

      kv::TxHistory::Result result = kv::TxHistory::Result::OK;

      sig.node = id;
      sig.sig = kp.sign_hash(sig.root.h.data(), sig.root.h.size());

      return result;
    }

    bool verify(
      kv::Term* term = nullptr, PrimarySignature* signature = nullptr) override
    {
      auto tx = store.create_read_only_tx();
      auto signatures =
        tx.template ro<ccf::Signatures>(ccf::Tables::SIGNATURES);
      auto sig = signatures->get();
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

      auto root = get_replicated_state_root();
      log_hash(root, VERIFY);
      return verify_node_signature(tx, sig_value.node, sig_value.sig, root);
    }

    std::vector<uint8_t> serialise_tree(size_t from, size_t to) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      return replicated_state_tree.serialise(from, to);
    }

    void set_term(kv::Term t) override
    {
      // This should only be called once, when the store first knows about its
      // term
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      term_of_last_version = t;
      term_of_next_version = t;
    }

    void rollback(
      const kv::TxID& tx_id, kv::Term term_of_next_version_) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      LOG_TRACE_FMT("Rollback to {}.{}", tx_id.term, tx_id.version);
      term_of_last_version = tx_id.term;
      term_of_next_version = term_of_next_version_;
      replicated_state_tree.retract(tx_id.version);
      log_hash(replicated_state_tree.get_root(), ROLLBACK);
    }

    void compact(kv::Version v) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      // Receipts can only be retrieved to the flushed index. Keep a range of
      // history so that a range of receipts are available.
      if (v > MAX_HISTORY_LEN)
      {
        replicated_state_tree.flush(v - MAX_HISTORY_LEN);
      }
      log_hash(replicated_state_tree.get_root(), COMPACT);
    }

    ccf::pal::Mutex signature_lock;

    void try_emit_signature() override
    {
      std::unique_lock<ccf::pal::Mutex> mguard(signature_lock, std::defer_lock);
      if (store.committable_gap() < sig_tx_interval || !mguard.try_lock())
      {
        return;
      }

      if (store.committable_gap() >= sig_tx_interval)
      {
        mguard.unlock();
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

      if (!endorsed_cert.has_value())
      {
        throw std::logic_error(
          fmt::format("No endorsed certificate set to emit signature"));
      }

      auto previous_signature_seqno =
        consensus->get_previous_committable_seqno();
      auto txid = store.next_txid();

      LOG_DEBUG_FMT(
        "Signed at {} in view: {}, previous signature was at {}",
        txid.version,
        txid.term,
        previous_signature_seqno);

      store.commit(
        txid,
        std::make_unique<MerkleTreeHistoryPendingTx<T>>(
          txid,
          previous_signature_seqno,
          store,
          *this,
          id,
          kp,
          endorsed_cert.value()),
        true);
    }

    std::vector<uint8_t> get_proof(kv::Version index) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      return replicated_state_tree.get_proof(index).to_v();
    }

    bool verify_proof(const std::vector<uint8_t>& v) override
    {
      Proof proof(v);
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      return replicated_state_tree.verify(proof);
    }

    std::vector<uint8_t> get_raw_leaf(uint64_t index) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      auto leaf = replicated_state_tree.get_leaf(index);
      return {leaf.h.begin(), leaf.h.end()};
    }

    void append(const std::vector<uint8_t>& data) override
    {
      crypto::Sha256Hash rh(data);
      log_hash(rh, APPEND);
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      replicated_state_tree.append(rh);
    }

    void append_entry(const crypto::Sha256Hash& digest) override
    {
      log_hash(digest, APPEND);
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      replicated_state_tree.append(digest);
    }

    void set_endorsed_certificate(const crypto::Pem& cert) override
    {
      endorsed_cert = cert;
    }
  };

  using MerkleTxHistory = HashedTxHistory<MerkleTreeHistory>;
}
