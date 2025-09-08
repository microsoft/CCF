// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/snapshotter.h"

#include "crypto/openssl/hash.h"
#include "ds/framework_logger.h"
#include "ds/ring_buffer.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"
#include "node/history.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#include <string>

constexpr auto buffer_size = 1024 * 16;
auto node_kp = ccf::crypto::make_key_pair();

using StringString = ccf::kv::Map<std::string, std::string>;
using rb_msg = std::pair<ringbuffer::Message, size_t>;

auto read_ringbuffer_out(ringbuffer::Circuit& circuit)
{
  std::optional<rb_msg> idx = std::nullopt;
  circuit.read_from_inside().read(
    -1, [&idx](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case ::consensus::snapshot_allocate:
        case ::consensus::snapshot_commit:
        {
          auto idx_ = serialized::read<::consensus::Index>(data, size);
          idx = {m, idx_};
          break;
        }
        default:
        {
          REQUIRE(false);
        }
      }
    });

  return idx;
}

auto read_snapshot_allocate_out(ringbuffer::Circuit& circuit)
{
  std::optional<std::tuple<::consensus::Index, size_t, uint32_t>>
    snapshot_allocate_out = std::nullopt;
  circuit.read_from_inside().read(
    -1,
    [&snapshot_allocate_out](
      ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case ::consensus::snapshot_allocate:
        {
          auto idx = serialized::read<::consensus::Index>(data, size);
          serialized::read<::consensus::Index>(data, size);
          auto requested_size = serialized::read<size_t>(data, size);
          auto generation_count = serialized::read<uint32_t>(data, size);

          snapshot_allocate_out = {idx, requested_size, generation_count};
          break;
        }
        case ::consensus::snapshot_commit:
        {
          REQUIRE(false);
          break;
        }
        default:
        {
          REQUIRE(false);
        }
      }
    });

  return snapshot_allocate_out;
}

void issue_transactions(ccf::NetworkState& network, size_t tx_count)
{
  for (size_t i = 0; i < tx_count; i++)
  {
    auto tx = network.tables->create_tx();
    auto map = tx.rw<StringString>("public:map");
    map->put("foo", "bar");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
}

size_t read_latest_snapshot_evidence(
  const std::shared_ptr<ccf::kv::Store>& store)
{
  auto tx = store->create_read_only_tx();
  auto h = tx.ro<ccf::SnapshotEvidence>(ccf::Tables::SNAPSHOT_EVIDENCE);
  auto evidence = h->get();
  if (!evidence.has_value())
  {
    throw std::logic_error("No snapshot evidence");
  }
  return evidence->version;
}

bool record_signature(
  const std::shared_ptr<ccf::MerkleTxHistory>& history,
  const std::shared_ptr<ccf::Snapshotter>& snapshotter,
  size_t idx)
{
  std::vector<uint8_t> dummy_signature(128, 43);
  ccf::crypto::Pem node_cert;

  bool requires_snapshot = snapshotter->record_committable(idx);
  snapshotter->record_signature(
    idx, dummy_signature, ccf::kv::test::PrimaryNodeId, node_cert);
  snapshotter->record_serialised_tree(idx, history->serialise_tree(idx));

  return requires_snapshot;
}

void record_snapshot_evidence(
  const std::shared_ptr<ccf::Snapshotter>& snapshotter,
  size_t snapshot_idx,
  size_t evidence_idx)
{
  snapshotter->record_snapshot_evidence_idx(
    evidence_idx, ccf::SnapshotHash{.version = snapshot_idx});
}

TEST_CASE("Regular snapshotting")
{
  ccf::logger::config::default_init();

  ccf::NetworkState network;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables.get(), ccf::kv::test::PrimaryNodeId, *node_kp);
  network.tables->set_history(history);
  network.tables->initialise_term(2);
  network.tables->set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);

  auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Circuit eio(in_buffer->bd, out_buffer->bd);

  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;

  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    *writer_factory, network.tables, snapshot_tx_interval);

  size_t commit_idx = 0;
  size_t snapshot_idx = snapshot_tx_interval;
  size_t snapshot_evidence_idx = snapshot_idx + 1;

  INFO("Generate snapshot before interval has no effect");
  {
    REQUIRE_FALSE(record_signature(history, snapshotter, snapshot_idx - 1));
    commit_idx = snapshot_idx - 1;
    snapshotter->commit(commit_idx, true);
    threading::ThreadMessaging::instance().run_one();

    REQUIRE_THROWS_AS(
      read_latest_snapshot_evidence(network.tables), std::logic_error);
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);
  }

  INFO("Malicious host");
  {
    REQUIRE(record_signature(history, snapshotter, snapshot_idx));

    // Note: even if commit_idx > snapshot_tx_interval, the snapshot is
    // generated at snapshot_idx
    commit_idx = snapshot_idx + 1;
    snapshotter->commit(commit_idx, true);

    threading::ThreadMessaging::instance().run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    auto snapshot_allocate_msg = read_snapshot_allocate_out(eio);
    REQUIRE(snapshot_allocate_msg.has_value());
    auto [snapshot_idx, snapshot_size, snapshot_count] =
      snapshot_allocate_msg.value();

    // Incorrect generation count
    {
      auto snapshot = std::vector<uint8_t>(snapshot_size);
      REQUIRE_FALSE(snapshotter->write_snapshot(snapshot, snapshot_count + 1));
    }

    // Incorrect size
    {
      auto snapshot = std::vector<uint8_t>(snapshot_size + 1);
      REQUIRE_FALSE(snapshotter->write_snapshot(snapshot, snapshot_count));
    }

    // Even if snapshot is now valid, pending snapshot was previously
    // discarded because of incorrect size
    {
      auto snapshot = std::vector<uint8_t>(snapshot_size);
      REQUIRE_FALSE(snapshotter->write_snapshot(snapshot, snapshot_count));
    }
  }

  INFO("Generate first snapshot");
  {
    issue_transactions(network, snapshot_tx_interval);
    snapshot_idx = 2 * snapshot_idx;
    REQUIRE(record_signature(history, snapshotter, snapshot_idx));

    // Note: even if commit_idx > snapshot_tx_interval, the snapshot is
    // generated at snapshot_idx
    commit_idx = snapshot_idx + 1;
    snapshotter->commit(commit_idx, true);

    threading::ThreadMessaging::instance().run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    auto snapshot_allocate_msg = read_snapshot_allocate_out(eio);
    REQUIRE(snapshot_allocate_msg.has_value());
    auto [snapshot_idx, snapshot_size, snapshot_count] =
      snapshot_allocate_msg.value();

    // Commit before snapshot is stored has no effect
    issue_transactions(network, 1);
    record_snapshot_evidence(snapshotter, snapshot_idx, snapshot_evidence_idx);
    commit_idx = snapshot_idx + 2;
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);

    // Correct size
    auto snapshot = std::vector<uint8_t>(snapshot_size, 0x00);
    REQUIRE(snapshotter->write_snapshot(snapshot, snapshot_count));
    // Snapshot is successfully populated
    REQUIRE(snapshot != std::vector<uint8_t>(snapshot_size, 0x00));
  }

  INFO("Commit first snapshot");
  {
    snapshotter->commit(commit_idx, true);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({::consensus::snapshot_commit, snapshot_idx}));
  }

  INFO("Subsequent commit before next snapshot idx has no effect");
  {
    commit_idx = snapshot_idx + 2;
    snapshotter->commit(commit_idx, true);
    threading::ThreadMessaging::instance().run_one();
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);
  }

  issue_transactions(network, snapshot_tx_interval - 2);

  INFO("Generate second snapshot");
  {
    snapshot_idx = snapshot_tx_interval * 3;
    snapshot_evidence_idx = snapshot_idx + 1;
    REQUIRE(record_signature(history, snapshotter, snapshot_idx));
    // Note: Commit exactly on snapshot idx
    commit_idx = snapshot_idx;
    snapshotter->commit(commit_idx, true);

    threading::ThreadMessaging::instance().run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    auto snapshot_allocate_msg = read_snapshot_allocate_out(eio);
    REQUIRE(snapshot_allocate_msg.has_value());
    auto [snapshot_idx, snapshot_size, snapshot_count] =
      snapshot_allocate_msg.value();
    auto snapshot = std::vector<uint8_t>(snapshot_size);
    REQUIRE(snapshotter->write_snapshot(snapshot, snapshot_count));
  }

  INFO("Commit second snapshot");
  {
    issue_transactions(network, 1);
    record_snapshot_evidence(snapshotter, snapshot_idx, snapshot_evidence_idx);
    // Signature after evidence is recorded
    commit_idx = snapshot_idx + 2;
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));

    snapshotter->commit(commit_idx, true);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({::consensus::snapshot_commit, snapshot_idx}));
  }
}

TEST_CASE("Rollback before snapshot is committed")
{
  ccf::NetworkState network;
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables.get(), ccf::kv::test::PrimaryNodeId, *node_kp);
  network.tables->set_history(history);
  network.tables->initialise_term(2);
  network.tables->set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);

  auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Circuit eio(in_buffer->bd, out_buffer->bd);

  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;
  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    *writer_factory, network.tables, snapshot_tx_interval);

  size_t snapshot_idx = 0;
  size_t commit_idx = 0;

  INFO("Generate snapshot");
  {
    snapshot_idx = snapshot_tx_interval;
    REQUIRE(record_signature(history, snapshotter, snapshot_idx));
    snapshotter->commit(snapshot_idx, true);

    threading::ThreadMessaging::instance().run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);

    auto snapshot_allocate_msg = read_snapshot_allocate_out(eio);
    REQUIRE(snapshot_allocate_msg.has_value());
    auto [snapshot_idx, snapshot_size, snapshot_count] =
      snapshot_allocate_msg.value();
    auto snapshot = std::vector<uint8_t>(snapshot_size);
    REQUIRE(snapshotter->write_snapshot(snapshot, snapshot_count));
  }

  INFO("Rollback evidence and commit past it");
  {
    snapshotter->rollback(snapshot_idx);

    // ... More transactions are committed, passing the idx at which the
    // evidence was originally committed

    snapshotter->commit(snapshot_tx_interval + 1, true);

    // Snapshot previously generated is not committed
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);

    snapshotter->commit(snapshot_tx_interval + 2, true);
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);
  }

  INFO("Snapshot again and commit evidence");
  {
    issue_transactions(network, snapshot_tx_interval);
    size_t snapshot_idx = network.tables->current_version();

    REQUIRE(record_signature(history, snapshotter, snapshot_idx));
    snapshotter->commit(snapshot_idx, true);

    threading::ThreadMessaging::instance().run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    auto snapshot_allocate_msg = read_snapshot_allocate_out(eio);
    REQUIRE(snapshot_allocate_msg.has_value());
    auto [snapshot_idx_, snapshot_size, snapshot_count] =
      snapshot_allocate_msg.value();
    REQUIRE(snapshot_idx == snapshot_idx_);
    auto snapshot = std::vector<uint8_t>(snapshot_size);
    REQUIRE(snapshotter->write_snapshot(snapshot, snapshot_count));

    // Commit evidence
    issue_transactions(network, 1);
    commit_idx = snapshot_idx + 2;
    record_snapshot_evidence(snapshotter, snapshot_idx, snapshot_idx + 1);
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({::consensus::snapshot_commit, snapshot_idx}));
  }

  INFO("Force a snapshot");
  {
    size_t snapshot_idx = network.tables->current_version();

    network.tables->set_flag(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);

    REQUIRE_FALSE(record_signature(history, snapshotter, snapshot_idx));
    snapshotter->commit(snapshot_idx, true);

    threading::ThreadMessaging::instance().run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    auto snapshot_allocate_msg = read_snapshot_allocate_out(eio);
    REQUIRE(snapshot_allocate_msg.has_value());
    auto [snapshot_idx_, snapshot_size, snapshot_count] =
      snapshot_allocate_msg.value();
    REQUIRE(snapshot_idx == snapshot_idx_);
    auto snapshot = std::vector<uint8_t>(snapshot_size);
    REQUIRE(snapshotter->write_snapshot(snapshot, snapshot_count));

    REQUIRE(!network.tables->flag_enabled(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));

    // Commit evidence
    issue_transactions(network, 1);
    commit_idx = snapshot_idx + 2;
    record_snapshot_evidence(snapshotter, snapshot_idx, snapshot_idx + 1);
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({::consensus::snapshot_commit, snapshot_idx}));

    threading::ThreadMessaging::instance().run_one();
  }
}

// https://github.com/microsoft/CCF/issues/3796
TEST_CASE("Rekey ledger while snapshot is in progress")
{
  ccf::logger::config::default_init();

  ccf::NetworkState network;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables.get(), ccf::kv::test::PrimaryNodeId, *node_kp);
  network.tables->set_history(history);
  network.tables->initialise_term(2);
  network.tables->set_consensus(consensus);
  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  ledger_secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(ledger_secrets);
  network.tables->set_encryptor(encryptor);

  auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Circuit eio(in_buffer->bd, out_buffer->bd);
  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;

  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    *writer_factory, network.tables, snapshot_tx_interval);

  size_t snapshot_idx = snapshot_tx_interval + 1;

  INFO("Trigger snapshot");
  {
    // It is necessary to record a signature for the snapshot to be
    // deserialisable by the backup store
    auto tx = network.tables->create_tx();
    auto sigs = tx.rw<ccf::Signatures>(ccf::Tables::SIGNATURES);
    auto trees =
      tx.rw<ccf::SerialisedMerkleTree>(ccf::Tables::SERIALISED_MERKLE_TREE);
    sigs->put({ccf::kv::test::PrimaryNodeId, 0, 0, {}, {}, {}, {}});
    auto tree = history->serialise_tree(snapshot_idx - 1);
    trees->put(tree);
    tx.commit();

    REQUIRE(record_signature(history, snapshotter, snapshot_idx));
    snapshotter->commit(snapshot_idx, true);

    // Do not schedule task just yet so that we can interleave ledger rekey
  }

  INFO("Rekey ledger and commit new transactions");
  {
    ledger_secrets->set_secret(snapshot_idx + 1, ccf::make_ledger_secret());

    // Issue new transactions that make use of new ledger secret
    issue_transactions(network, snapshot_tx_interval);
  }

  INFO("Finally, schedule snapshot creation");
  {
    threading::ThreadMessaging::instance().run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    auto snapshot_allocate_msg = read_snapshot_allocate_out(eio);
    REQUIRE(snapshot_allocate_msg.has_value());
    auto [snapshot_idx_, snapshot_size, snapshot_count] =
      snapshot_allocate_msg.value();
    REQUIRE(snapshot_idx == snapshot_idx_);
    auto snapshot = std::vector<uint8_t>(snapshot_size);
    REQUIRE(snapshotter->write_snapshot(snapshot, snapshot_count));

    // Snapshot can be deserialised to backup store
    ccf::NetworkState backup_network;
    auto backup_history = std::make_shared<ccf::MerkleTxHistory>(
      *backup_network.tables.get(), ccf::kv::test::FirstBackupNodeId, *node_kp);
    backup_network.tables->set_history(backup_history);
    auto tx = network.tables->create_read_only_tx();

    auto backup_ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
    backup_ledger_secrets->init_from_map(ledger_secrets->get(tx));
    auto backup_encryptor =
      std::make_shared<ccf::NodeEncryptor>(backup_ledger_secrets);
    backup_network.tables->set_encryptor(backup_encryptor);

    ccf::kv::ConsensusHookPtrs hooks;
    std::vector<ccf::kv::Version> view_history;
    REQUIRE(
      backup_network.tables->deserialise_snapshot(
        snapshot.data(), snapshot.size(), hooks, &view_history) ==
      ccf::kv::ApplyResult::PASS);
  }
}

int main(int argc, char** argv)
{
  threading::ThreadMessaging::init(1);
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
