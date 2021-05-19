// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/logger.h"
#include "kv/test/null_encryptor.h"
#include "node/snapshotter.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>

// Because snapshot serialisation is costly, the snapshotter serialises
// snapshots asynchronously.
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 1;
threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
constexpr auto buffer_size = 1024 * 16;

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

TEST_CASE("Regular snapshotting")
{
  ccf::NetworkState network;

  auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Circuit eio(in_buffer->bd, out_buffer->bd);

  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;
  size_t interval_count = 3;

  issue_transactions(network, snapshot_tx_interval * interval_count);

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    *writer_factory, network.tables, snapshot_tx_interval);

  REQUIRE_FALSE(snapshotter->record_committable(snapshot_tx_interval - 1));
  REQUIRE(snapshotter->record_committable(snapshot_tx_interval));
  REQUIRE(snapshotter->record_committable(snapshot_tx_interval * 2));
  REQUIRE(
    snapshotter->record_committable(snapshot_tx_interval * interval_count));

  size_t commit_idx = 0;
  INFO("Generate snapshot before first snapshot idx has no effect");
  {
    commit_idx = snapshot_tx_interval - 1;
    snapshotter->commit(commit_idx, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);
  }

  INFO("Generate first snapshot");
  {
    // Note: even if commit_idx > snapshot_tx_interval, the snapshot is
    // generated for the previous snapshot
    auto snapshot_idx = snapshot_tx_interval;
    commit_idx = snapshot_idx + 1;
    snapshotter->commit(commit_idx, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) == rb_msg({consensus::snapshot, snapshot_idx}));
  }

  INFO("Subsequent commit before next snapshot idx has no effect");
  {
    commit_idx = snapshot_tx_interval + 2;
    snapshotter->commit(commit_idx, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);
  }

  INFO("Generate second snapshot");
  {
    // Note: Commit exactly on snapshot idx
    auto snapshot_idx = snapshot_tx_interval * 2;
    commit_idx = snapshot_idx;
    snapshotter->commit(commit_idx, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) == rb_msg({consensus::snapshot, snapshot_idx}));
  }

  INFO("Subsequent commit before next snapshot idx has no effect");
  {
    commit_idx = snapshot_tx_interval * 2 + 1;
    snapshotter->commit(commit_idx, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);
  }

  INFO("Generate third snapshot");
  {
    auto snapshot_idx = (snapshot_tx_interval * interval_count);
    commit_idx = snapshot_idx + 1;
    snapshotter->commit(commit_idx, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) == rb_msg({consensus::snapshot, snapshot_idx}));
  }

  INFO("Cannot snapshot before latest snapshot");
  {
    commit_idx = (snapshot_tx_interval * interval_count) - 1;
    REQUIRE_THROWS_AS(snapshotter->commit(commit_idx, true), std::logic_error);
  }
}

TEST_CASE("Commit snapshot evidence")
{
  ccf::NetworkState network;

  auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Circuit eio(in_buffer->bd, out_buffer->bd);

  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;
  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    *writer_factory, network.tables, snapshot_tx_interval);

  INFO("Generate snapshot");
  {
    snapshotter->record_committable(snapshot_tx_interval);
    snapshotter->commit(snapshot_tx_interval, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot, snapshot_tx_interval}));
  }

  INFO("Commit evidence");
  {
    // This assumes that the evidence was committed just after the snasphot, at
    // idx = (snapshot_tx_interval + 1)

    // First commit marks evidence as committed but no commit message is emitted
    // yet
    snapshotter->commit(snapshot_tx_interval + 1, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);

    // Second commit passed evidence commit, snapshot is committed
    snapshotter->commit(snapshot_tx_interval + 2, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot_commit, snapshot_tx_interval}));
  }
}

TEST_CASE("Rollback before evidence is committed")
{
  ccf::NetworkState network;

  auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Circuit eio(in_buffer->bd, out_buffer->bd);

  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;
  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    *writer_factory, network.tables, snapshot_tx_interval);

  INFO("Generate snapshot");
  {
    snapshotter->record_committable(snapshot_tx_interval);
    snapshotter->commit(snapshot_tx_interval, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot, snapshot_tx_interval}));
  }

  INFO("Rollback evidence and commit past it");
  {
    snapshotter->rollback(snapshot_tx_interval);

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

    snapshotter->record_committable(snapshot_idx);
    snapshotter->commit(snapshot_idx, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) == rb_msg({consensus::snapshot, snapshot_idx}));

    // Commit evidence
    snapshotter->commit(snapshot_idx + 1, true);
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);

    // Evidence proof is committed
    snapshotter->commit(snapshot_idx + 2, true);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot_commit, snapshot_idx}));
  }
}