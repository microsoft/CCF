// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/snapshotter.h"

#include "ds/logger.h"
#include "kv/test/null_encryptor.h"

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
    *writer_factory, network, snapshot_tx_interval);

  REQUIRE_FALSE(snapshotter->record_committable(snapshot_tx_interval - 1));
  REQUIRE(snapshotter->record_committable(snapshot_tx_interval));

  INFO("Generate snapshots at regular intervals");
  {
    for (size_t i = 1; i <= interval_count; i++)
    {
      // No snapshot generated if < interval
      snapshotter->update(i * (snapshot_tx_interval - 1), true);
      threading::ThreadMessaging::thread_messaging.run_one();
      REQUIRE(read_ringbuffer_out(eio) == std::nullopt);

      snapshotter->update(i * snapshot_tx_interval, true);
      threading::ThreadMessaging::thread_messaging.run_one();
      REQUIRE(
        read_ringbuffer_out(eio) ==
        rb_msg({consensus::snapshot, (i * snapshot_tx_interval)}));
    }
  }

  INFO("Cannot snapshot before latest snapshot");
  {
    REQUIRE_THROWS_AS(
      snapshotter->update(snapshot_tx_interval - 1, true), std::logic_error);
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
    *writer_factory, network, snapshot_tx_interval);

  INFO("Generate snapshot");
  {
    snapshotter->update(snapshot_tx_interval, true);
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
    snapshotter->commit(snapshot_tx_interval + 1);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);

    // Second commit passed evidence commit, snapshot is committed
    snapshotter->commit(snapshot_tx_interval + 2);
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
    *writer_factory, network, snapshot_tx_interval);

  INFO("Generate snapshot");
  {
    snapshotter->update(snapshot_tx_interval, true);
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

    snapshotter->commit(snapshot_tx_interval + 1);

    // Snapshot previously generated is not committed
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);
  }

  INFO("Snapshot again and commit evidence");
  {
    issue_transactions(network, snapshot_tx_interval);

    size_t snapshot_idx = network.tables->current_version();
    snapshotter->update(snapshot_idx, true);
    threading::ThreadMessaging::thread_messaging.run_one();
    REQUIRE(
      read_ringbuffer_out(eio) == rb_msg({consensus::snapshot, snapshot_idx}));

    // Commit evidence
    snapshotter->commit(snapshot_idx + 1);
    REQUIRE(read_ringbuffer_out(eio) == std::nullopt);

    // Evidence proof is committed
    snapshotter->commit(snapshot_idx + 2);
    REQUIRE(
      read_ringbuffer_out(eio) ==
      rb_msg({consensus::snapshot_commit, snapshot_idx}));
  }
}