// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/logger.h"
#include "kv/test/null_encryptor.h"
#include "node/network_state.h"
#include "node/snapshotter.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>

std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 1;
threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;

using StringString = kv::Map<std::string, std::string>;

auto read_ringbuffer_out(ringbuffer::Circuit& circuit)
{
  std::optional<size_t> generated_snapshot_idx = std::nullopt;
  circuit.read_from_inside().read(
    -1,
    [&generated_snapshot_idx](
      ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case consensus::snapshot:
        {
          auto idx = serialized::read<consensus::Index>(data, size);
          generated_snapshot_idx = idx;
          break;
        }
        default:
        {
          REQUIRE(false);
        }
      }
    });

  return generated_snapshot_idx;
}

TEST_CASE("Simple snapshots")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  ccf::NetworkState network;
  network.tables->set_encryptor(encryptor);
  ringbuffer::Circuit eio(1024 * 16);
  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;
  size_t interval_count = 3;

  INFO("Initialise store");
  {
    for (size_t i = 0; i < snapshot_tx_interval * interval_count; i++)
    {
      auto tx = network.tables->create_tx();
      auto view = tx.get_view2<StringString>("map");
      view->put("foo", "bar");
      REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    }
  }

  auto snapshotter =
    std::make_shared<ccf::Snapshotter>(*writer_factory, network);
  snapshotter->set_tx_interval(snapshot_tx_interval);

  REQUIRE_FALSE(snapshotter->requires_snapshot(snapshot_tx_interval - 1));
  REQUIRE(snapshotter->requires_snapshot(snapshot_tx_interval));

  INFO("Generated snapshots at regular intervals");
  {
    for (size_t i = 1; i <= interval_count; i++)
    {
      snapshotter->snapshot(i * (snapshot_tx_interval - 1));
      threading::ThreadMessaging::thread_messaging.run_one();
      REQUIRE(read_ringbuffer_out(eio) == std::nullopt);

      snapshotter->snapshot(i * snapshot_tx_interval);
      threading::ThreadMessaging::thread_messaging.run_one();

      REQUIRE(read_ringbuffer_out(eio) == (i * snapshot_tx_interval));
    }
  }
}