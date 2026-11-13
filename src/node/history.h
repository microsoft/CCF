// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_key.h"
#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/mldsa_key_pair.h"
#include "ccf/ds/locking.h"
#include "ccf/ds/x509_time_fmt.h"
#include "ccf/node/ledger_sign_mode.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/service.h"
#include "crypto/cose.h"
#include "crypto/openssl/ec_key_pair.h"
#include "crypto/openssl/hash.h"
#include "crypto/openssl/mldsa_support.h"
#include "crypto/public_key.h"
#include "ds/internal_logger.h"
#include "endian.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "node/cose_common.h"
#include "node/no_get_ledger_sign_mode.cpp" // NOLINT(bugprone-suspicious-include)
#include "node_signature_verify.h"
#include "service/tables/signatures.h"
#include "service/tables/signing_identities.h"
#include "tasks/basic_task.h"
#include "tasks/task_system.h"

#include <array>
#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <span>
#include <string.h>
#include <vector>

#define HAVE_OPENSSL
// merklecpp traces are off by default, even when CCF tracing is enabled
// #include "merklecpp_trace.h"
#include <merklecpp/merklecpp.h>

namespace ccf
{
  enum HashOp : uint8_t
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
      {
        os << "append";
        break;
      }

      case VERIFY:
      {
        os << "verify";
        break;
      }

      case ROLLBACK:
      {
        os << "rollback";
        break;
      }

      case COMPACT:
      {
        os << "compact";
        break;
      }
    }

    return os;
  }

  static inline void log_hash(const ccf::crypto::Sha256Hash& h, HashOp flag)
  {
    LOG_TRACE_FMT("History [{}] {}", flag, h);
  }

  // Use optimised CCF openssl_sha256 function to avoid performance regression
  // on OpenSSL 3.x
  static constexpr size_t sha256_byte_size = 32;

  static inline void sha256_history(
    const merkle::HashT<sha256_byte_size>& l,
    const merkle::HashT<sha256_byte_size>& r,
    merkle::HashT<sha256_byte_size>& out)

  {
    uint8_t block[sha256_byte_size * 2];
    memcpy(&block[0], l.bytes, sha256_byte_size);
    memcpy(&block[sha256_byte_size], r.bytes, sha256_byte_size);

    ccf::crypto::openssl_sha256(block, out.bytes);
  }

  using HistoryTree = merkle::TreeT<sha256_byte_size, ccf::sha256_history>;

  class Proof
  {
  private:
    HistoryTree::Hash root;
    std::shared_ptr<HistoryTree::Path> path = nullptr;

  public:
    Proof() = default;

    Proof(const std::vector<uint8_t>& v)
    {
      size_t position = 0;
      root.deserialise(v, position);
      path = std::make_shared<HistoryTree::Path>(v, position);
    }

    [[nodiscard]] const HistoryTree::Hash& get_root() const
    {
      return root;
    }

    std::shared_ptr<HistoryTree::Path> get_path()
    {
      return path;
    }

    Proof(HistoryTree* tree, uint64_t index) :
      root(tree->root()),
      path(tree->path(index))
    {}

    Proof(const Proof&) = delete;

    bool verify(HistoryTree* tree) const
    {
      if (path->max_index() > tree->max_index())
      {
        return false;
      }

      if (tree->max_index() == path->max_index())
      {
        return tree->root() == root && path->verify(root);
      }

      auto past_root = tree->past_root(path->max_index());
      return path->verify(*past_root);
    }

    [[nodiscard]] std::vector<uint8_t> to_v() const
    {
      std::vector<uint8_t> v;
      root.serialise(v);
      path->serialise(v);
      return v;
    }
  };

  // Encodes the inclusion proof carried by a COSE receipt, for the leaf with
  // these components and its path in a HistoryTree
  static inline std::vector<uint8_t> encode_merkle_proof(
    const ccf::crypto::Sha256Hash& write_set_digest,
    const std::string& commit_evidence,
    const ccf::crypto::Sha256Hash& claims_digest,
    const HistoryTree::Path& path)
  {
    cose::MerkleProof proof;
    proof.leaf.write_set_digest.assign(
      write_set_digest.h.begin(), write_set_digest.h.end());
    proof.leaf.commit_evidence = commit_evidence;
    proof.leaf.claims_digest.assign(
      claims_digest.h.begin(), claims_digest.h.end());
    for (const auto& element : path)
    {
      proof.path.emplace_back(
        element.direction == HistoryTree::Path::Direction::PATH_LEFT ? 1 : 0,
        std::vector<uint8_t>(
          element.hash.bytes, element.hash.bytes + element.hash.size()));
    }
    return cose::encode_merkle_proof(proof);
  }

  template <class T>
  class MerkleTreeHistoryPendingTx : public ccf::kv::PendingTx
  {
    ccf::TxID txid;
    ccf::kv::Store& store;
    ccf::kv::TxHistory& history;
    NodeId id;
    ccf::crypto::ECKeyPair& node_kp;
    ccf::crypto::ECKeyPair_OpenSSL& service_kp;
    // nullptr for a service without an ML-DSA identity
    ccf::crypto::MLDSAKeyPairPtr pq_service_kp;
    std::shared_ptr<const ccf::crypto::Pem> endorsed_cert;
    const ccf::COSESignaturesConfig& cose_signatures_config;
    const ccf::LedgerSignMode ledger_sign_mode;

  public:
    MerkleTreeHistoryPendingTx(
      ccf::TxID txid_,
      ccf::kv::Store& store_,
      ccf::kv::TxHistory& history_,
      NodeId id_,
      ccf::crypto::ECKeyPair& node_kp_,
      ccf::crypto::ECKeyPair_OpenSSL& service_kp_,
      ccf::crypto::MLDSAKeyPairPtr pq_service_kp_,
      std::shared_ptr<const ccf::crypto::Pem> endorsed_cert_,
      const ccf::COSESignaturesConfig& cose_signatures_config_,
      ccf::LedgerSignMode ledger_sign_mode_) :
      txid(txid_),
      store(store_),
      history(history_),
      id(std::move(id_)),
      node_kp(node_kp_),
      service_kp(service_kp_),
      pq_service_kp(std::move(pq_service_kp_)),
      endorsed_cert(std::move(endorsed_cert_)),
      cose_signatures_config(cose_signatures_config_),
      ledger_sign_mode(ledger_sign_mode_)
    {}

    ccf::kv::PendingTxInfo call() override
    {
      auto sig = store.create_reserved_tx(txid);
      ccf::crypto::Sha256Hash root = history.get_replicated_state_root();

      std::vector<uint8_t> root_hash{
        root.h.data(), root.h.data() + root.h.size()};

      if (ledger_sign_mode == ccf::LedgerSignMode::Dual)
      {
        auto* signatures =
          sig.template wo<ccf::Signatures>(ccf::Tables::SIGNATURES);
        auto primary_sig =
          node_kp.sign_hash(root_hash.data(), root_hash.size());

        PrimarySignature sig_value(
          id,
          txid.seqno,
          txid.view,
          root,
          {}, // Nonce is currently empty
          primary_sig,
          *endorsed_cert);

        signatures->put(sig_value);
      }

      auto* cose_signatures =
        sig.template wo<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);

      const auto tx_id = txid.to_str();

      const auto time_since_epoch =
        std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

      // One signature per service signing key, with the same protected header
      // except alg and kid
      const auto sign = [&](const auto& key) {
        return cose::sign_ledger(
          key,
          ccf::crypto::kid_from_key(key.public_key_der()),
          time_since_epoch,
          cose_signatures_config.issuer,
          cose_signatures_config.subject,
          tx_id,
          root_hash);
      };

      cose_signatures->put(ccf::IdentityType::CLASSICAL, sign(service_kp));
      if (pq_service_kp != nullptr)
      {
        cose_signatures->put(ccf::IdentityType::PQ, sign(*pq_service_kp));
      }

      auto* serialised_tree = sig.template wo<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      serialised_tree->put(history.serialise_tree(txid.seqno - 1));

      return sig.commit_reserved();
    }
  };

  class MerkleTreeHistory
  {
    std::unique_ptr<HistoryTree> tree;

  public:
    MerkleTreeHistory(MerkleTreeHistory const&) = delete;

    MerkleTreeHistory(const std::vector<uint8_t>& serialised) :
      tree(std::make_unique<HistoryTree>(serialised))
    {}

    MerkleTreeHistory(ccf::crypto::Sha256Hash first_hash = {}) :
      tree(std::make_unique<HistoryTree>(merkle::Hash(first_hash.h)))
    {}

    ~MerkleTreeHistory() = default;

    void deserialise(const std::vector<uint8_t>& serialised)
    {
      tree = std::make_unique<HistoryTree>(serialised);
    }

    void append(const ccf::crypto::Sha256Hash& hash)
    {
      tree->insert(merkle::Hash(hash.h));
    }

    [[nodiscard]] ccf::crypto::Sha256Hash get_root() const
    {
      const merkle::Hash& root = tree->root();
      ccf::crypto::Sha256Hash result;
      std::copy(root.bytes, root.bytes + root.size(), result.h.begin());
      return result;
    }

    MerkleTreeHistory& operator=(const MerkleTreeHistory& rhs)
    {
      if (this != &rhs)
      {
        ccf::crypto::Sha256Hash root(rhs.get_root());
        tree = std::make_unique<HistoryTree>(merkle::Hash(root.h));
      }
      return *this;
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
          "Cannot produce proof for {}: index is older than first index {}, "
          "and has been flushed from memory",
          index,
          begin_index()));
      }
      if (index > end_index())
      {
        throw std::logic_error(fmt::format(
          "Cannot produce proof for {}: index is later than last index {}",
          index,
          end_index()));
      }
      return {tree.get(), index};
    }

    bool verify(const Proof& r)
    {
      return r.verify(tree.get());
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

    ccf::crypto::Sha256Hash get_leaf(uint64_t index)
    {
      const merkle::Hash& leaf = tree->leaf(index);
      ccf::crypto::Sha256Hash result;
      std::copy(leaf.bytes, leaf.bytes + leaf.size(), result.h.begin());
      return result;
    }
  };

  template <class T>
  class HashedTxHistory : public ccf::kv::TxHistory
  {
    ccf::kv::Store& store;
    NodeId id;
    T replicated_state_tree;

    ccf::crypto::ECKeyPair& node_kp;

    struct CachedCOSEVerifier
    {
      ccf::Identity identity;
      ccf::crypto::COSEVerifierUniquePtr verifier;
    };

    // One verifier per identity type, rebuilt when the published identity of
    // that type changes
    std::map<ccf::IdentityType, CachedCOSEVerifier> cose_verifiers;

    ccf::tasks::Task emit_signature_periodic_task;
    size_t sig_tx_interval;
    size_t sig_ms_interval;

    // Set by start_signature_emit_timer(), once the node is part of the
    // network and may sign. Until then, try_emit_signature() does nothing,
    // so that a signature triggered by an unrelated request cannot precede
    // this node's certificate in the ledger (e.g. the create transaction at
    // the end of public recovery), which would make it unverifiable on replay.
    std::atomic<bool> signing_enabled = false;

    ccf::ds::Mutex state_lock;
    ccf::kv::Term term_of_last_version = 0;
    ccf::kv::Term term_of_next_version{};

    std::atomic<std::shared_ptr<const ccf::crypto::Pem>> endorsed_cert =
      nullptr;

    struct ServiceSigningIdentity
    {
      const std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> service_kp;
      // nullptr for a service without an ML-DSA identity
      const ccf::crypto::MLDSAKeyPairPtr pq_service_kp;
      const ccf::COSESignaturesConfig cose_signatures_config;
      const ccf::LedgerSignMode ledger_sign_mode = ccf::LedgerSignMode::Dual;
    };

    std::optional<ServiceSigningIdentity> signing_identity = std::nullopt;

  public:
    HashedTxHistory(
      ccf::kv::Store& store_,
      NodeId id_,
      ccf::crypto::ECKeyPair& node_kp_,
      size_t sig_tx_interval_ = 0,
      size_t sig_ms_interval_ = 0,
      bool signature_timer = false) :
      store(store_),
      id(std::move(id_)),
      node_kp(node_kp_),
      sig_tx_interval(sig_tx_interval_),
      sig_ms_interval(sig_ms_interval_)
    {
      if (signature_timer)
      {
        start_signature_emit_timer();
      }
    }

    void set_service_signing_identity(
      std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> service_kp_,
      ccf::crypto::MLDSAKeyPairPtr pq_service_kp_,
      const ccf::COSESignaturesConfig& cose_signatures_config_) override
    {
      if (signing_identity.has_value())
      {
        throw std::logic_error(
          "Called set_service_signing_identity() multiple times");
      }

      const auto ledger_sign_mode_ = ccf::get_ledger_sign_mode();

      std::string pq_key_description = "none";
      if (pq_service_kp_ != nullptr)
      {
        pq_key_description =
          nlohmann::json(pq_service_kp_->get_parameter_set()).dump();
      }

      signing_identity.emplace(ServiceSigningIdentity{
        service_kp_,
        pq_service_kp_,
        cose_signatures_config_,
        ledger_sign_mode_});

      LOG_INFO_FMT(
        "Setting service signing identity to iss: {} sub: {}. Ledger "
        "signature mode: {}. ML-DSA key: {}",
        cose_signatures_config_.issuer,
        cose_signatures_config_.subject,
        nlohmann::json(ledger_sign_mode_).dump(),
        pq_key_description);
    }

    const ccf::COSESignaturesConfig& get_cose_signatures_config() override
    {
      if (!signing_identity.has_value())
      {
        throw std::logic_error(
          "Called get_cose_signatures_config() before "
          "set_service_signing_identity()");
      }

      return signing_identity->cose_signatures_config;
    }

    void start_signature_emit_timer() override
    {
      signing_enabled.store(true, std::memory_order_release);

      const auto delay = std::chrono::milliseconds(sig_ms_interval);

      emit_signature_periodic_task = ccf::tasks::make_basic_task([this]() {
        std::unique_lock<ccf::ds::Mutex> mguard(
          this->signature_lock, std::defer_lock);

        bool should_emit_signature = false;

        if (mguard.try_lock())
        {
          auto consensus = this->store.get_consensus();
          if (consensus != nullptr)
          {
            auto sig_disp = consensus->get_signature_disposition();
            switch (sig_disp)
            {
              case ccf::kv::Consensus::SignatureDisposition::CANT_REPLICATE:
              {
                break;
              }
              case ccf::kv::Consensus::SignatureDisposition::CAN_SIGN:
              {
                // To snapshot we need to complete the chunk and to do that we
                // need to set the force_chunk_after flag on the last snapshot
                // in it.
                // At this point the previous signature is already replicating
                // and is immutable.
                // So if we need to snapshot, we need to emit a new signature to
                // ensure we can set the force_chunk_after flag, even if there
                // are no other transactions between this and the last snapshot
                if (
                  this->store.committable_gap() > 0 ||
                  this->store.should_schedule_snapshot())
                {
                  should_emit_signature = true;
                }
                break;
              }
              case ccf::kv::Consensus::SignatureDisposition::SHOULD_SIGN:
              {
                should_emit_signature = true;
                break;
              }
            }
          }
        }

        if (should_emit_signature)
        {
          this->emit_signature();
        }
      });

      ccf::tasks::add_periodic_task(emit_signature_periodic_task, delay, delay);
    }

    ~HashedTxHistory() override
    {
      if (emit_signature_periodic_task != nullptr)
      {
        emit_signature_periodic_task->cancel_task();
      }
    }

    void set_node_id(const NodeId& id_)
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
      auto* tree_h = tx.template ro<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      auto tree = tree_h->get();
      if (!tree.has_value())
      {
        LOG_FAIL_FMT("No tree found in serialised tree map");
        return false;
      }

      // Delay taking this lock until _after_ the read above, to avoid lock
      // inversions
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);

      CCF_ASSERT_FMT(
        !replicated_state_tree.in_range(1),
        "Tree is not empty before initialising from snapshot");

      replicated_state_tree.deserialise(tree.value());

      ccf::crypto::Sha256Hash hash;
      std::copy_n(
        hash_at_snapshot.begin(),
        ccf::crypto::Sha256Hash::SIZE,
        hash.h.begin());
      replicated_state_tree.append(hash);
      return true;
    }

    ccf::crypto::Sha256Hash get_replicated_state_root() override
    {
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      return replicated_state_tree.get_root();
    }

    std::tuple<ccf::TxID, ccf::crypto::Sha256Hash, ccf::kv::Term>
    get_replicated_state_txid_and_root() override
    {
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      return {
        {term_of_last_version,
         static_cast<ccf::kv::Version>(replicated_state_tree.end_index())},
        replicated_state_tree.get_root(),
        term_of_next_version};
    }

    bool verify_root_signatures(ccf::kv::Version version) override
    {
      auto tx = store.create_read_only_tx();

      // Since COSE signatures have not always been emitted, it is possible in a
      // mixed-service to see an _old_ COSE signature (by reading from the KV)
      // that does not refer to the _current root_. When this occurs
      // version_of_previous_write will not match the version at which we're
      // verifying.
      const auto cose_signatures = get_cose_signatures_written_at(tx, version);
      for (const auto& signature : cose_signatures)
      {
        const auto identity_type = signature.first;
        if (!can_verify(identity_type))
        {
          throw_unverifiable(fmt::format(
            "Transaction {} carries a {} signature, which this build cannot "
            "verify",
            version,
            identity_type));
        }
      }

      auto root = get_replicated_state_root();
      log_hash(root, VERIFY);

      size_t signatures_passed = 0;

      // Only verify the node signature if it was actually written in this
      // version. In COSE-only mode, the signatures table is not written,
      // so an old value may be present from a previous dual-signed
      // transaction. Verifying that stale signature against the current
      // root would fail.
      auto* signatures =
        tx.template ro<ccf::Signatures>(ccf::Tables::SIGNATURES);
      auto sig = signatures->get();
      const auto sig_version = signatures->get_version_of_previous_write();
      if (
        sig.has_value() && sig_version.has_value() &&
        sig_version.value() == version)
      {
        if (!verify_node_signature(tx, sig->node, sig->sig, root))
        {
          return false;
        }
        signatures_passed++;
      }

      std::vector<uint8_t> root_hash{
        root.h.data(), root.h.data() + root.h.size()};
      for (const auto& [identity_type, cose_signature] : cose_signatures)
      {
        if (!verify_cose_signature(
              tx, version, identity_type, cose_signature, root_hash))
        {
          return false;
        }
        signatures_passed++;
      }

      if (!is_signed_by_every_signing_identity(tx, version, cose_signatures))
      {
        return false;
      }

      if (signatures_passed == 0)
      {
        LOG_FAIL_FMT("No signatures found in transaction {}", version);
      }

      return signatures_passed > 0;
    }

    std::vector<uint8_t> serialise_tree(size_t to) override
    {
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      if (to <= replicated_state_tree.end_index())
      {
        return replicated_state_tree.serialise(
          replicated_state_tree.begin_index(), to);
      }

      return {};
    }

    void set_term(ccf::kv::Term t) override
    {
      // This should only be called once, when the store first knows about its
      // term
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      term_of_last_version = t;
      term_of_next_version = t;
    }

    void rollback(
      const ccf::TxID& tx_id, ccf::kv::Term term_of_next_version_) override
    {
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      LOG_TRACE_FMT("Rollback to {}.{}", tx_id.view, tx_id.seqno);
      term_of_last_version = tx_id.view;
      term_of_next_version = term_of_next_version_;
      replicated_state_tree.retract(tx_id.seqno);
      log_hash(replicated_state_tree.get_root(), ROLLBACK);
    }

    void compact(ccf::kv::Version v) override
    {
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      // Receipts can only be retrieved to the flushed index. Keep a range of
      // history so that a range of receipts are available.
      if (v > MAX_HISTORY_LEN)
      {
        replicated_state_tree.flush(v - MAX_HISTORY_LEN);
      }
      log_hash(replicated_state_tree.get_root(), COMPACT);
    }

    ccf::ds::Mutex signature_lock;

    void try_emit_signature() override
    {
      if (!signing_enabled.load(std::memory_order_acquire))
      {
        return;
      }

      std::unique_lock<ccf::ds::Mutex> mguard(signature_lock, std::defer_lock);
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

      auto endorsed_cert_ = endorsed_cert.load(std::memory_order_acquire);
      if (endorsed_cert_ == nullptr)
      {
        throw std::logic_error(
          fmt::format("No endorsed certificate set to emit signature"));
      }

      auto txid = store.next_txid();

      LOG_DEBUG_FMT("Signed at {} in view: {}", txid.seqno, txid.view);

      if (!signing_identity.has_value())
      {
        throw std::logic_error(
          fmt::format("No service key has been set yet to sign"));
      }

      store.commit(
        txid,
        std::make_unique<MerkleTreeHistoryPendingTx<T>>(
          txid,
          store,
          *this,
          id,
          node_kp,
          *signing_identity->service_kp,
          signing_identity->pq_service_kp,
          std::move(endorsed_cert_),
          signing_identity->cose_signatures_config,
          signing_identity->ledger_sign_mode),
        true);
    }

    std::vector<uint8_t> get_proof(ccf::kv::Version index) override
    {
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      return replicated_state_tree.get_proof(index).to_v();
    }

    bool verify_proof(const std::vector<uint8_t>& v) override
    {
      Proof proof(v);
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      return replicated_state_tree.verify(proof);
    }

    std::vector<uint8_t> get_raw_leaf(uint64_t index) override
    {
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      auto leaf = replicated_state_tree.get_leaf(index);
      return {leaf.h.begin(), leaf.h.end()};
    }

    void append(const std::vector<uint8_t>& data) override
    {
      ccf::crypto::Sha256Hash rh(data);
      log_hash(rh, APPEND);
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      replicated_state_tree.append(rh);
    }

    void append_entry(
      const ccf::crypto::Sha256Hash& digest,
      std::optional<ccf::kv::Term> expected_term_of_next_version =
        std::nullopt) override
    {
      log_hash(digest, APPEND);
      std::lock_guard<ccf::ds::Mutex> guard(state_lock);
      if (expected_term_of_next_version.has_value())
      {
        if (expected_term_of_next_version.value() != term_of_next_version)
        {
          return;
        }
      }
      replicated_state_tree.append(digest);
    }

    void set_endorsed_certificate(const ccf::crypto::Pem& cert) override
    {
      endorsed_cert.store(
        std::make_shared<const ccf::crypto::Pem>(cert),
        std::memory_order_release);
    }

  private:
    // Logs the cause at FAIL for every caller, since raft logs exceptions from
    // apply() at DEBUG
    [[noreturn]] static void throw_unverifiable(const std::string& msg)
    {
      LOG_FAIL_FMT("{}", msg);
      throw ccf::kv::UnverifiableSignatureType(msg);
    }

    // COSE signatures written by the transaction at version, by identity type
    static ccf::CoseSignatureMap get_cose_signatures_written_at(
      ccf::kv::ReadOnlyTx& tx, ccf::kv::Version version)
    {
      auto* cose_signatures =
        tx.template ro<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);

      std::vector<ccf::IdentityType> identity_types;
      try
      {
        cose_signatures->foreach_key(
          [&identity_types](const ccf::IdentityType& identity_type) {
            identity_types.push_back(identity_type);
            return true;
          });
      }
      catch (const std::exception& e)
      {
        throw_unverifiable(fmt::format(
          "Cannot read the identity types of the COSE signatures in "
          "transaction {}: {}",
          version,
          e.what()));
      }

      ccf::CoseSignatureMap written;
      for (const auto identity_type : identity_types)
      {
        const auto written_at =
          cose_signatures->get_version_of_previous_write(identity_type);
        if (!written_at.has_value() || written_at.value() != version)
        {
          continue;
        }
        auto cose_signature = cose_signatures->get(identity_type);
        if (cose_signature.has_value())
        {
          written.emplace(identity_type, std::move(cose_signature.value()));
        }
      }
      return written;
    }

    static bool can_verify(ccf::IdentityType identity_type)
    {
      switch (identity_type)
      {
        case ccf::IdentityType::CLASSICAL:
        {
          return true;
        }
        case ccf::IdentityType::PQ:
        {
          return ccf::crypto::mldsa_supported();
        }
      }
      return false;
    }

    bool verify_cose_signature(
      ccf::kv::ReadOnlyTx& tx,
      ccf::kv::Version version,
      ccf::IdentityType identity_type,
      const ccf::CoseSignature& cose_signature,
      std::span<const uint8_t> root_hash)
    {
      // CLASSICAL falls back to the service certificate, as in ledgers written
      // before the signing identities table existed
      try
      {
        const auto service_signing_identity =
          ccf::get_service_signing_identity(tx, identity_type);
        if (!service_signing_identity.has_value())
        {
          LOG_FAIL_FMT(
            "No {} service signing identity found to verify the signature in "
            "transaction {}",
            identity_type,
            version);
          return false;
        }

        if (!cose_verifier_cached(
               identity_type, service_signing_identity.value())
               .verify_detached(cose_signature, root_hash))
        {
          LOG_FAIL_FMT(
            "{} signature in transaction {} failed to verify",
            identity_type,
            version);
          return false;
        }
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Cannot verify the {} signature in transaction {}: {}",
          identity_type,
          version,
          e.what());
        return false;
      }

      if (ccf::logger::config::ok(LoggerLevel::DEBUG))
      {
        try
        {
          auto receipt = ccf::cose::decode_ccf_receipt(
            cose_signature, /* recompute_root */ false);
          if (receipt.phdr.cwt.iat.has_value())
          {
            LOG_DEBUG_FMT(
              "Verified {} COSE signature for TxID {}, issued at {}",
              identity_type,
              receipt.phdr.ccf.txid,
              ccf::ds::to_x509_time_string(
                std::chrono::system_clock::from_time_t(
                  receipt.phdr.cwt.iat.value())));
          }
        }
        catch (const std::exception& e)
        {
          LOG_DEBUG_FMT(
            "Failed to decode COSE protected header for debug logging: {}",
            e.what());
        }
      }

      return true;
    }

    // Every service signing identity published by the time of the transaction
    // at version must have signed it
    static bool is_signed_by_every_signing_identity(
      ccf::kv::ReadOnlyTx& tx,
      ccf::kv::Version version,
      const ccf::CoseSignatureMap& cose_signatures)
    {
      std::vector<ccf::IdentityType> published;
      try
      {
        tx.template ro<ccf::SigningIdentities>(ccf::Tables::SIGNING_IDENTITIES)
          ->foreach_key([&published](const ccf::IdentityType& identity_type) {
            published.push_back(identity_type);
            return true;
          });
      }
      catch (const std::exception& e)
      {
        throw_unverifiable(fmt::format(
          "Cannot read the identity types of the service signing identities "
          "to verify transaction {}: {}",
          version,
          e.what()));
      }

      for (const auto identity_type : published)
      {
        if (!cose_signatures.contains(identity_type))
        {
          LOG_FAIL_FMT(
            "Transaction {} has no {} signature, although a {} service "
            "signing identity is published",
            version,
            identity_type,
            identity_type);
          return false;
        }
      }
      return true;
    }

    const ccf::crypto::COSEVerifier& cose_verifier_cached(
      ccf::IdentityType identity_type, const ccf::Identity& identity)
    {
      auto& cached = cose_verifiers[identity_type];
      if (cached.verifier == nullptr || cached.identity != identity)
      {
        cached.verifier = ccf::crypto::make_cose_verifier_from_key(
          cose_key_from_identity(identity));
        cached.identity = identity;
      }
      return *cached.verifier;
    }
  };

  using MerkleTxHistory = HashedTxHistory<MerkleTreeHistory>;
}
