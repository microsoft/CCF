// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/snapshotter.h"

#include "ds/logger.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/history.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>

// Because snapshot serialisation is costly, the snapshotter serialises
// snapshots asynchronously.
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 1;
threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
constexpr auto buffer_size = 1024 * 16;
auto kp = crypto::make_key_pair();

using StringString = kv::Map<std::string, std::string>;
using rb_msg = std::pair<ringbuffer::Message, size_t>;

auto read_ringbuffer_out(ringbuffer::Circuit& circuit)
{
  std::optional<rb_msg> idx = std::nullopt;
  circuit.read_from_inside().read(
    -1, [&idx](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case consensus::snapshot:
        case consensus::snapshot_commit:
        {
          auto idx_ = serialized::read<consensus::Index>(data, size);
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

void issue_transactions(ccf::NetworkState& network, size_t tx_count)
{
  for (size_t i = 0; i < tx_count; i++)
  {
    auto tx = network.tables->create_tx();
    auto map = tx.rw<StringString>("public:map");
    map->put("foo", "bar");
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }
}

size_t read_latest_snapshot_evidence(const std::shared_ptr<kv::Store>& store)
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
  crypto::Pem node_cert;

  bool requires_snapshot = snapshotter->record_committable(idx);
  snapshotter->record_signature(
    idx, dummy_signature, kv::test::PrimaryNodeId, node_cert);
  snapshotter->record_serialised_tree(idx, history->serialise_tree(1, idx));

  return requires_snapshot;
}

TEST_CASE("Regular snapshotting")
{
  ccf::NetworkState network;

  auto consensus = std::make_shared<kv::test::StubConsensus>();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables.get(), kv::test::PrimaryNodeId, *kp);
  network.tables->set_history(history);
  network.tables->set_consensus(consensus);

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

  INFO("Generate snapshot before interval has no effect");
  {
    REQUIRE_FALSE(record_signature(history, snapshotter, snapshot_idx - 1));
    commit_idx = snapshot_idx - 1;
    snapshotter->commit(commit_idx, true);
    threading::ThreadMessaging::thread_messaging.run_one();

    REQUIRE_THROWS_AS(
      read_latest_snapshot_evidence(network.tables), std::logic_error);
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);
  }

  INFO("Generate first snapshot");
  {
    REQUIRE(record_signature(history, snapshotter, snapshot_tx_interval));

    // Note: even if commit_idx > snapshot_tx_interval, the snapshot is
    // generated at snapshot_idx
    commit_idx = snapshot_idx + 1;
    snapshotter->commit(commit_idx, true);

    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    REQUIRE(
      read_ringbuffer_out(eio) == rb_msg({consensus::snapshot, snapshot_idx}));
  }

  INFO("Commit first snapshot");
  {
    issue_transactions(network, 1);
    // Signature after evidence is recorded
    commit_idx = snapshot_tx_interval + 2;
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot_commit, snapshot_idx}));
  }

  INFO("Subsequent commit before next snapshot idx has no effect");
  {
    commit_idx = snapshot_tx_interval + 2;
    snapshotter->commit(commit_idx, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);
  }

  issue_transactions(network, snapshot_tx_interval - 2);

  INFO("Generate second snapshot");
  {
    snapshot_idx = snapshot_tx_interval * 2;
    REQUIRE(record_signature(history, snapshotter, snapshot_idx));
    // Note: Commit exactly on snapshot idx
    commit_idx = snapshot_idx;
    snapshotter->commit(commit_idx, true);

    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    REQUIRE(
      read_ringbuffer_out(eio) == rb_msg({consensus::snapshot, snapshot_idx}));
  }

  INFO("Commit second snapshot");
  {
    issue_transactions(network, 1);
    // Signature after evidence is recorded
    commit_idx = snapshot_tx_interval * 2 + 2;
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));

    snapshotter->commit(commit_idx, true);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot_commit, snapshot_idx}));
  }
}

TEST_CASE("Rollback before snapshot is committed")
{
  ccf::NetworkState network;
  auto consensus = std::make_shared<kv::test::StubConsensus>();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables.get(), kv::test::PrimaryNodeId, *kp);
  network.tables->set_history(history);
  network.tables->set_consensus(consensus);

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

    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot, snapshot_tx_interval}));
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

    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    REQUIRE(
      read_ringbuffer_out(eio) == rb_msg({consensus::snapshot, snapshot_idx}));

    // Commit evidence
    issue_transactions(network, 1);
    commit_idx = snapshot_idx + 2;
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot_commit, snapshot_idx}));
  }
}