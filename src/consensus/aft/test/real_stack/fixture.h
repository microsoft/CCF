// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// A harness combining a real ccf::kv::Store, a real
// aft::Aft<aft::LedgerStubProxy> (raft consensus), and a real
// ccf::MerkleTxHistory, for tests that exercise how these three components
// interact under real concurrency. Other unit tests exercise each of these
// components in isolation, with lighter-weight stubs standing in for the
// others.
//
// LedgerStubProxy and ChannelStubProxy remain stubs here: they are the
// host-disk and network I/O boundaries, not part of what this suite tests.

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/ds/x509_time_fmt.h"
#include "ccf/service/consensus_config.h"
#include "consensus/aft/raft.h"
#include "consensus/aft/test/logging_stub.h"
#include "crypto/certs.h"
#include "crypto/openssl/ec_key_pair.h"
#include "kv/ledger_chunker.h"
#include "kv/store.h"
#include "kv/test/interleaving.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"
#include "node/history.h"
#include "node/ledger_secrets.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <set>

namespace ccf::kv::test
{
  using RealStackRaft = aft::Aft<aft::LedgerStubProxy>;
  using RealStackTable = ccf::kv::Map<size_t, size_t>;

  class CheckpointedMerkleTxHistory : public ccf::MerkleTxHistory
  {
    std::atomic<Checkpoint*> before_next_append = nullptr;
    std::atomic<Checkpoint*> after_next_append = nullptr;

  public:
    using ccf::MerkleTxHistory::MerkleTxHistory;

    void pause_before_next_append_entry(Checkpoint& checkpoint)
    {
      before_next_append.store(&checkpoint);
    }

    void pause_after_next_append_entry(Checkpoint& checkpoint)
    {
      after_next_append.store(&checkpoint);
    }

    void append_entry(
      const ccf::crypto::Sha256Hash& digest,
      std::optional<ccf::kv::Term> expected_term = std::nullopt) override
    {
      if (auto* checkpoint = before_next_append.exchange(nullptr))
      {
        checkpoint->pause();
      }

      ccf::MerkleTxHistory::append_entry(digest, expected_term);

      if (auto* checkpoint = after_next_append.exchange(nullptr))
      {
        checkpoint->pause();
      }
    }
  };

  class InspectableLedgerChunker : public ccf::kv::LedgerChunker
  {
    std::atomic<Checkpoint*> after_next_append = nullptr;

  public:
    // NB: Store::commit() holds version_lock across append_entry_size(), so a
    // controller thread released by this checkpoint must not drive a Store
    // rollback while the worker is still paused here - it would deadlock. Use
    // step_down(), which does not touch the KV, rather than reelect().
    void pause_after_next_append_entry_size(Checkpoint& checkpoint)
    {
      after_next_append.store(&checkpoint);
    }

    void append_entry_size(size_t size) override
    {
      ccf::kv::LedgerChunker::append_entry_size(size);
      if (auto* checkpoint = after_next_append.exchange(nullptr))
      {
        checkpoint->pause();
      }
    }

    ccf::kv::Version current_version()
    {
      ccf::pal::MutexGuard guard(chunker_lock);
      return current_tx_version;
    }

    bool has_chunk_end(ccf::kv::Version version)
    {
      ccf::pal::MutexGuard guard(chunker_lock);
      return chunk_ends.contains(version);
    }

    bool has_forced_chunk(ccf::kv::Version version)
    {
      ccf::pal::MutexGuard guard(chunker_lock);
      return forced_chunk_versions.contains(version);
    }
  };

  class CheckpointedRealStackRaft : public RealStackRaft
  {
    std::atomic<Checkpoint*> after_next_replicate = nullptr;

  public:
    using RealStackRaft::RealStackRaft;

    void pause_after_next_replicate_call(Checkpoint& checkpoint)
    {
      after_next_replicate.store(&checkpoint);
    }

    bool replicate(
      const ccf::kv::BatchVector& entries, ccf::kv::Term term) override
    {
      const auto result = RealStackRaft::replicate(entries, term);
      if (auto* checkpoint = after_next_replicate.exchange(nullptr))
      {
        checkpoint->pause();
      }
      return result;
    }
  };

  class InspectableSnapshotter : public ccf::kv::AbstractSnapshotter
  {
    std::mutex lock;
    std::set<ccf::kv::Version> recorded_committable;

  public:
    bool record_committable(ccf::kv::Version version) override
    {
      std::lock_guard<std::mutex> guard(lock);
      recorded_committable.insert(version);
      return true;
    }

    bool should_schedule_snapshot(ccf::kv::Version) override
    {
      return false;
    }

    void commit(ccf::kv::Version, bool) override {}

    void rollback(ccf::kv::Version version) override
    {
      std::lock_guard<std::mutex> guard(lock);
      recorded_committable.erase(
        recorded_committable.upper_bound(version), recorded_committable.end());
    }

    bool has_recorded(ccf::kv::Version version)
    {
      std::lock_guard<std::mutex> guard(lock);
      return recorded_committable.contains(version);
    }
  };

  inline const ccf::consensus::Configuration& real_stack_raft_settings()
  {
    static const ccf::consensus::Configuration settings{
      ccf::ds::TimeString{"10ms"}, ccf::ds::TimeString{"100ms"}, 0};
    return settings;
  }

  inline std::optional<size_t> read_value(
    ccf::kv::Store& store, RealStackTable& table, size_t key)
  {
    auto tx = store.create_read_only_tx();
    return tx.ro(table)->get(key);
  }

  // A harness combining the real stack described above, plus helpers for
  // driving genuine raft view changes (which in turn trigger genuine
  // Store::rollback() calls, exactly as a production election would).
  struct RealStackFixture
  {
    const ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;
    // Used only as the notional sender of the fake RequestVote messages
    // step_down() constructs below - never actually configured as a real
    // peer.
    const ccf::NodeId phantom_peer = ccf::NodeId("RealStackFixturePhantomPeer");
    std::shared_ptr<ccf::crypto::ECKeyPair> node_kp =
      ccf::crypto::make_ec_key_pair();
    std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> service_kp =
      std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
        ccf::crypto::make_ec_key_pair());
    std::shared_ptr<ccf::kv::Store> store = std::make_shared<ccf::kv::Store>();
    std::shared_ptr<CheckpointedMerkleTxHistory> history;
    std::shared_ptr<InspectableLedgerChunker> chunker =
      std::make_shared<InspectableLedgerChunker>();
    std::shared_ptr<InspectableSnapshotter> snapshotter;
    std::shared_ptr<CheckpointedRealStackRaft> raft;
    RealStackTable table{"public:table"};
    ccf::View initial_view = 0;

    // use_real_crypto selects between NullTxEncryptor (default: fast enough
    // for a tight fuzzing loop) and a real ccf::NodeEncryptor (slower, but
    // exercises real AES-GCM IV/nonce derivation - relevant to catching
    // nonce-reuse-across-rollback style bugs that NullTxEncryptor cannot).
    explicit RealStackFixture(bool use_real_crypto = false)
    {
      if (use_real_crypto)
      {
        auto secrets = std::make_shared<ccf::LedgerSecrets>();
        secrets->init();
        store->set_encryptor(std::make_shared<ccf::NodeEncryptor>(secrets));
      }
      else
      {
        store->set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
      }

      history = std::make_shared<CheckpointedMerkleTxHistory>(
        *store, node_id, *node_kp);

      // Set up a signing identity so that commit_signature() below can
      // later emit a real signature transaction.
      constexpr size_t certificate_validity_period_days = 365;
      const auto valid_from = ccf::ds::to_x509_time_string(
        std::chrono::system_clock::now() - std::chrono::hours(24));
      const auto valid_to = ccf::crypto::compute_cert_valid_to_string(
        valid_from, certificate_validity_period_days);
      const auto self_signed =
        node_kp->self_sign("CN=Node", valid_from, valid_to);
      history->set_endorsed_certificate(self_signed);
      history->set_service_signing_identity(
        service_kp, ccf::COSESignaturesConfig{});
      store->set_history(history);
      store->set_chunker(chunker);

      raft = std::make_shared<CheckpointedRealStackRaft>(
        real_stack_raft_settings(),
        std::make_unique<aft::Adaptor<ccf::kv::Store>>(store),
        std::make_unique<aft::LedgerStubProxy>(node_id),
        std::make_shared<aft::ChannelStubProxy>(),
        std::make_shared<aft::State>(node_id),
        nullptr);
      store->set_consensus(raft);

      ccf::kv::Configuration::Nodes configuration;
      configuration.try_emplace(node_id);
      raft->add_configuration(0, configuration);
      raft->force_become_primary();
      initial_view = raft->get_view();
    }

    void install_inspectable_snapshotter()
    {
      snapshotter = std::make_shared<InspectableSnapshotter>();
      store->set_snapshotter(snapshotter);
    }

    // Makes this node aware of a higher term, safely, from any thread.
    //
    // Aft::become_aware_of_new_term() assumes its caller already holds
    // Aft's own (private) state lock, so calling it directly here would
    // race against another thread's concurrent Store::commit() ->
    // replicate(). recv_message() is Aft's self-locked public entry point
    // for this instead, so this constructs a minimal RequestVote from an
    // unconfigured phantom peer and delivers it through that path - as a
    // real node would learn of a higher term from a real peer.
    // term_of_last_committable_idx is set to the new term, which always
    // beats this node's own (never advanced after setup), so the vote is
    // granted and leadership is relinquished before force_become_primary()
    // is next called.
    void step_down()
    {
      const auto next_term = raft->get_view() + 1;
      aft::RequestVote rv;
      rv.term = next_term;
      rv.term_of_last_committable_idx = next_term;
      rv.last_committable_idx = 0;
      raft->recv_message(
        phantom_peer, reinterpret_cast<const uint8_t*>(&rv), sizeof(rv));
    }

    // Loses leadership (rolling back any uncommitted local writes, as a real
    // node would when it discovers a higher term) and then wins the next
    // election. Returns the new view.
    ccf::View reelect()
    {
      step_down();
      raft->force_become_primary();
      return raft->get_view();
    }

    // Emits a real signature transaction, which - like production CCF's
    // periodic signature emission - is the mechanism that marks the current
    // point globally committable, letting raft's own commit index advance
    // past it. Returns the TxID of the signature transaction itself.
    ccf::TxID commit_signature()
    {
      const auto before = store->current_txid();
      history->emit_signature();
      const auto after = store->current_txid();
      if (after.seqno == before.seqno)
      {
        throw std::logic_error("emit_signature() did not advance the store");
      }
      return after;
    }

    // TxHistory's own idea of the last TxID it has recorded.
    //
    // The returned TxID's view is only refreshed by rollback()/set_term(),
    // not by every append_entry() call, so it matches
    // store->current_txid().view only immediately after a rollback, before
    // any further commit in the new term. For an ordinary in-term commit,
    // compare seqnos only (see history_term_of_next_version() below for
    // the current term).
    ccf::TxID history_txid()
    {
      auto [txid, root, term_of_next_version] =
        history->get_replicated_state_txid_and_root();
      (void)root;
      (void)term_of_next_version;
      return txid;
    }

    // TxHistory's own idea of the current term (i.e. the term new entries
    // are expected to be appended in) - the third element of
    // get_replicated_state_txid_and_root(), tracked and used independently
    // of the TxID's own .view (see history_txid() above).
    ccf::kv::Term history_term_of_next_version()
    {
      auto [txid, root, term_of_next_version] =
        history->get_replicated_state_txid_and_root();
      (void)txid;
      (void)root;
      return term_of_next_version;
    }
  };
}
