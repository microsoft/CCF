// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/locking.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/service.h"
#include "crypto/openssl/cose_sign.h"
#include "crypto/openssl/hash.h"
#include "crypto/openssl/key_pair.h"
#include "ds/thread_messaging.h"
#include "enclave/enclave_time.h"
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
struct formatter<ccf::kv::TxHistory::RequestID>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::kv::TxHistory::RequestID& p, FormatContext& ctx) const
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

  static inline void log_hash(const ccf::crypto::Sha256Hash& h, HashOp flag)
  {
    LOG_TRACE_FMT("History [{}] {}", flag, h);
  }

  class NullTxHistoryPendingTx : public ccf::kv::PendingTx
  {
    ccf::kv::TxID txid;
    ccf::kv::Store& store;
    NodeId id;

  public:
    NullTxHistoryPendingTx(
      ccf::kv::TxID txid_, ccf::kv::Store& store_, const NodeId& id_) :
      txid(txid_),
      store(store_),
      id(id_)
    {}

    ccf::kv::PendingTxInfo call() override
    {
      auto sig = store.create_reserved_tx(txid);
      auto signatures =
        sig.template wo<ccf::Signatures>(ccf::Tables::SIGNATURES);
      auto cose_signatures =
        sig.template wo<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);

      auto serialised_tree = sig.template wo<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      PrimarySignature sig_value(id, txid.version);
      signatures->put(sig_value);
      cose_signatures->put(ccf::CoseSignature{});
      serialised_tree->put({});
      return sig.commit_reserved();
    }
  };

  class NullTxHistory : public ccf::kv::TxHistory
  {
    ccf::kv::Store& store;
    NodeId id;

  protected:
    ccf::kv::Version version = 0;
    ccf::kv::Term term_of_last_version = 0;
    ccf::kv::Term term_of_next_version = 0;

  public:
    NullTxHistory(
      ccf::kv::Store& store_, const NodeId& id_, ccf::crypto::KeyPair&) :
      store(store_),
      id(id_)
    {}

    void append(const std::vector<uint8_t>&) override
    {
      version++;
    }

    void append_entry(
      const ccf::crypto::Sha256Hash& digest,
      std::optional<ccf::kv::Term> term_of_next_version_ =
        std::nullopt) override
    {
      version++;
    }

    bool verify_root_signatures() override
    {
      return true;
    }

    void set_term(ccf::kv::Term t) override
    {
      term_of_last_version = t;
      term_of_next_version = t;
    }

    void rollback(
      const ccf::kv::TxID& tx_id, ccf::kv::Term commit_term_) override
    {
      version = tx_id.version;
      term_of_last_version = tx_id.term;
      term_of_next_version = commit_term_;
    }

    void compact(ccf::kv::Version) override {}

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

    void set_service_signing_identity(
      std::shared_ptr<ccf::crypto::KeyPair_OpenSSL> service_kp_,
      const ccf::COSESignaturesConfig& cose_signatures) override
    {
      std::ignore = std::move(service_kp_);
    }

    const ccf::COSESignaturesConfig& get_cose_signatures_config() override
    {
      throw std::logic_error("Unimplemented");
    }

    ccf::crypto::Sha256Hash get_replicated_state_root() override
    {
      return ccf::crypto::Sha256Hash(std::to_string(version));
    }

    std::tuple<ccf::kv::TxID, ccf::crypto::Sha256Hash, ccf::kv::Term>
    get_replicated_state_txid_and_root() override
    {
      return {
        {term_of_last_version, version},
        ccf::crypto::Sha256Hash(std::to_string(version)),
        term_of_next_version};
    }

    std::vector<uint8_t> get_proof(ccf::kv::Version) override
    {
      return {};
    }

    bool verify_proof(const std::vector<uint8_t>&) override
    {
      return true;
    }

    std::vector<uint8_t> serialise_tree(size_t) override
    {
      return {};
    }

    void set_endorsed_certificate(const ccf::crypto::Pem& cert) override {}
  };

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
  class MerkleTreeHistoryPendingTx : public ccf::kv::PendingTx
  {
    ccf::kv::TxID txid;
    ccf::kv::Store& store;
    ccf::kv::TxHistory& history;
    NodeId id;
    ccf::crypto::KeyPair& node_kp;
    ccf::crypto::KeyPair_OpenSSL& service_kp;
    ccf::crypto::Pem& endorsed_cert;
    const ccf::COSESignaturesConfig& cose_signatures_config;

  public:
    MerkleTreeHistoryPendingTx(
      ccf::kv::TxID txid_,
      ccf::kv::Store& store_,
      ccf::kv::TxHistory& history_,
      const NodeId& id_,
      ccf::crypto::KeyPair& node_kp_,
      ccf::crypto::KeyPair_OpenSSL& service_kp_,
      ccf::crypto::Pem& endorsed_cert_,
      const ccf::COSESignaturesConfig& cose_signatures_config_) :
      txid(txid_),
      store(store_),
      history(history_),
      id(id_),
      node_kp(node_kp_),
      service_kp(service_kp_),
      endorsed_cert(endorsed_cert_),
      cose_signatures_config(cose_signatures_config_)
    {}

    ccf::kv::PendingTxInfo call() override
    {
      auto sig = store.create_reserved_tx(txid);
      auto signatures =
        sig.template wo<ccf::Signatures>(ccf::Tables::SIGNATURES);
      auto cose_signatures =
        sig.template wo<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);
      auto serialised_tree = sig.template wo<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      ccf::crypto::Sha256Hash root = history.get_replicated_state_root();

      std::vector<uint8_t> primary_sig;

      std::vector<uint8_t> root_hash{
        root.h.data(), root.h.data() + root.h.size()};
      primary_sig = node_kp.sign_hash(root_hash.data(), root_hash.size());

      PrimarySignature sig_value(
        id,
        txid.version,
        txid.term,
        root,
        {}, // Nonce is currently empty
        primary_sig,
        endorsed_cert);

      constexpr int64_t vds_merkle_tree = 2;

      const auto& service_key_der = service_kp.public_key_der();
      auto kid = ccf::crypto::Sha256Hash(service_key_der).hex_str();
      std::span<const uint8_t> kid_span{(uint8_t*)kid.data(), kid.size()};

      const auto time_since_epoch =
        std::chrono::duration_cast<std::chrono::seconds>(
          ccf::get_enclave_time())
          .count();

      auto ccf_headers =
        std::static_pointer_cast<ccf::crypto::COSEParametersFactory>(
          std::make_shared<ccf::crypto::COSEParametersMap>(
            std::make_shared<ccf::crypto::COSEMapStringKey>(
              ccf::crypto::COSE_PHEADER_KEY_CCF),
            ccf::crypto::COSEHeadersArray{
              ccf::crypto::cose_params_string_string(
                ccf::crypto::COSE_PHEADER_KEY_TXID, txid.str())}));

      auto cwt_headers =
        std::static_pointer_cast<ccf::crypto::COSEParametersFactory>(
          std::make_shared<ccf::crypto::COSEParametersMap>(
            std::make_shared<ccf::crypto::COSEMapIntKey>(
              ccf::crypto::COSE_PHEADER_KEY_CWT),
            ccf::crypto::COSEHeadersArray{
              ccf::crypto::cose_params_int_int(
                ccf::crypto::COSE_PHEADER_KEY_IAT, time_since_epoch),
              ccf::crypto::cose_params_int_string(
                ccf::crypto::COSE_PHEADER_KEY_ISS,
                cose_signatures_config.issuer),
              ccf::crypto::cose_params_int_string(
                ccf::crypto::COSE_PHEADER_KEY_SUB,
                cose_signatures_config.subject),
            }));

      const auto pheaders = {
        // Key digest
        ccf::crypto::cose_params_int_bytes(
          ccf::crypto::COSE_PHEADER_KEY_ID, kid_span),
        // VDS
        ccf::crypto::cose_params_int_int(
          ccf::crypto::COSE_PHEADER_KEY_VDS, vds_merkle_tree),
        // CWT claims
        cwt_headers,
        // CCF headers
        ccf_headers};

      auto cose_sign = crypto::cose_sign1(service_kp, pheaders, root_hash);

      signatures->put(sig_value);
      cose_signatures->put(cose_sign);
      serialised_tree->put(history.serialise_tree(txid.version - 1));
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

    MerkleTreeHistory(ccf::crypto::Sha256Hash first_hash = {})
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

    void append(const ccf::crypto::Sha256Hash& hash)
    {
      tree->insert(merkle::Hash(hash.h));
    }

    ccf::crypto::Sha256Hash get_root() const
    {
      const merkle::Hash& root = tree->root();
      ccf::crypto::Sha256Hash result;
      std::copy(root.bytes, root.bytes + root.size(), result.h.begin());
      return result;
    }

    void operator=(const MerkleTreeHistory& rhs)
    {
      delete (tree);
      ccf::crypto::Sha256Hash root(rhs.get_root());
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

    ccf::crypto::KeyPair& node_kp;
    ccf::crypto::COSEVerifierUniquePtr cose_verifier{};
    std::vector<uint8_t> cose_cert_cached{};

    std::optional<::threading::TaskQueue::TimerEntry>
      emit_signature_timer_entry = std::nullopt;
    size_t sig_tx_interval;
    size_t sig_ms_interval;

    ccf::pal::Mutex state_lock;
    ccf::kv::Term term_of_last_version = 0;
    ccf::kv::Term term_of_next_version;

    std::optional<ccf::crypto::Pem> endorsed_cert = std::nullopt;

    struct ServiceSigningIdentity
    {
      const std::shared_ptr<ccf::crypto::KeyPair_OpenSSL> service_kp;
      const ccf::COSESignaturesConfig cose_signatures_config;
    };

    std::optional<ServiceSigningIdentity> signing_identity = std::nullopt;

  public:
    HashedTxHistory(
      ccf::kv::Store& store_,
      const NodeId& id_,
      ccf::crypto::KeyPair& node_kp_,
      size_t sig_tx_interval_ = 0,
      size_t sig_ms_interval_ = 0,
      bool signature_timer = false) :
      store(store_),
      id(id_),
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
      std::shared_ptr<ccf::crypto::KeyPair_OpenSSL> service_kp_,
      const ccf::COSESignaturesConfig& cose_signatures_config_) override
    {
      if (signing_identity.has_value())
      {
        throw std::logic_error(
          "Called set_service_signing_identity() multiple times");
      }

      signing_identity.emplace(
        ServiceSigningIdentity{service_kp_, cose_signatures_config_});

      LOG_INFO_FMT(
        "Setting service signing identity to iss: {} sub: {}",
        cose_signatures_config_.issuer,
        cose_signatures_config_.subject);
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
      struct EmitSigMsg
      {
        EmitSigMsg(HashedTxHistory<T>* self_) : self(self_) {}
        HashedTxHistory<T>* self;
      };

      auto emit_sig_msg = std::make_unique<::threading::Tmsg<EmitSigMsg>>(
        [](std::unique_ptr<::threading::Tmsg<EmitSigMsg>> msg) {
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
                case ccf::kv::Consensus::SignatureDisposition::CANT_REPLICATE:
                {
                  break;
                }
                case ccf::kv::Consensus::SignatureDisposition::CAN_SIGN:
                {
                  if (self->store.committable_gap() > 0)
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
            msg->data.self->emit_signature();
          }

          self->emit_signature_timer_entry =
            ::threading::ThreadMessaging::instance().add_task_after(
              std::move(msg), std::chrono::milliseconds(self->sig_ms_interval));
        },
        this);

      emit_signature_timer_entry =
        ::threading::ThreadMessaging::instance().add_task_after(
          std::move(emit_sig_msg), std::chrono::milliseconds(sig_ms_interval));
    }

    ~HashedTxHistory()
    {
      if (emit_signature_timer_entry.has_value())
      {
        ::threading::ThreadMessaging::instance().cancel_timer_task(
          *emit_signature_timer_entry);
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
      auto tree_h = tx.template ro<ccf::SerialisedMerkleTree>(
        ccf::Tables::SERIALISED_MERKLE_TREE);
      auto tree = tree_h->get();
      if (!tree.has_value())
      {
        LOG_FAIL_FMT("No tree found in serialised tree map");
        return false;
      }

      // Delay taking this lock until _after_ the read above, to avoid lock
      // inversions
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);

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
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      return replicated_state_tree.get_root();
    }

    std::tuple<ccf::kv::TxID, ccf::crypto::Sha256Hash, ccf::kv::Term>
    get_replicated_state_txid_and_root() override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      return {
        {term_of_last_version,
         static_cast<ccf::kv::Version>(replicated_state_tree.end_index())},
        replicated_state_tree.get_root(),
        term_of_next_version};
    }

    bool verify_root_signatures() override
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

      auto root = get_replicated_state_root();
      log_hash(root, VERIFY);
      if (!verify_node_signature(tx, sig->node, sig->sig, root))
      {
        return false;
      }

      auto cose_signatures =
        tx.template ro<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);
      auto cose_sig = cose_signatures->get();

      if (!cose_sig.has_value())
      {
        return true;
      }

      auto service = tx.template ro<ccf::Service>(Tables::SERVICE);
      auto service_info = service->get();

      if (!service_info.has_value())
      {
        LOG_FAIL_FMT("No service key found to verify the signature");
        return false;
      }

      const auto raw_cert = service_info->cert.raw();
      std::vector<uint8_t> root_hash{
        root.h.data(), root.h.data() + root.h.size()};

      return cose_verifier_cached(raw_cert)->verify_detached(
        cose_sig.value(), root_hash);
    }

    std::vector<uint8_t> serialise_tree(size_t to) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      if (to <= replicated_state_tree.end_index())
      {
        return replicated_state_tree.serialise(
          replicated_state_tree.begin_index(), to);
      }
      else
      {
        return {};
      }
    }

    void set_term(ccf::kv::Term t) override
    {
      // This should only be called once, when the store first knows about its
      // term
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      term_of_last_version = t;
      term_of_next_version = t;
    }

    void rollback(
      const ccf::kv::TxID& tx_id, ccf::kv::Term term_of_next_version_) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      LOG_TRACE_FMT("Rollback to {}.{}", tx_id.term, tx_id.version);
      term_of_last_version = tx_id.term;
      term_of_next_version = term_of_next_version_;
      replicated_state_tree.retract(tx_id.version);
      log_hash(replicated_state_tree.get_root(), ROLLBACK);
    }

    void compact(ccf::kv::Version v) override
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

      auto txid = store.next_txid();

      LOG_DEBUG_FMT("Signed at {} in view: {}", txid.version, txid.term);

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
          endorsed_cert.value(),
          signing_identity->cose_signatures_config),
        true);
    }

    std::vector<uint8_t> get_proof(ccf::kv::Version index) override
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
      ccf::crypto::Sha256Hash rh(data);
      log_hash(rh, APPEND);
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
      replicated_state_tree.append(rh);
    }

    void append_entry(
      const ccf::crypto::Sha256Hash& digest,
      std::optional<ccf::kv::Term> expected_term_of_next_version =
        std::nullopt) override
    {
      log_hash(digest, APPEND);
      std::lock_guard<ccf::pal::Mutex> guard(state_lock);
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
      endorsed_cert = cert;
    }

  private:
    ccf::crypto::COSEVerifierUniquePtr& cose_verifier_cached(
      const std::vector<uint8_t>& cert)
    {
      if (cert != cose_cert_cached)
      {
        cose_cert_cached = cert;
        cose_verifier =
          ccf::crypto::make_cose_verifier_from_cert(cose_cert_cached);
      }
      return cose_verifier;
    }
  };

  using MerkleTxHistory = HashedTxHistory<MerkleTreeHistory>;
}
