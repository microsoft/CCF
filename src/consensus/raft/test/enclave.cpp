// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "consensus/ledger_enclave.h"
#include "ds/ring_buffer.h"
#include "tls/key_pair.h"

#include <doctest/doctest.h>

#undef FAIL

using namespace consensus;

using WFactory = ringbuffer::WriterFactory;

TEST_CASE("Enclave put")
{
  ringbuffer::Circuit eio(1024);
  std::unique_ptr<WFactory> writer_factory = std::make_unique<WFactory>(eio);

  auto enclave = LedgerEnclave(*writer_factory);

  const std::vector<uint8_t> tx = {'a', 'b', 'c'};
  enclave.put_entry(tx);
  size_t num_msgs = 0;
  eio.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case consensus::ledger_append:
        {
          REQUIRE(num_msgs == 0);
          auto entry = std::vector<uint8_t>(data, data + size);
          REQUIRE(entry == tx);
        }
        break;
        default:
          REQUIRE(false);
      }
      ++num_msgs;
    });
  REQUIRE(num_msgs == 1);
}

TEST_CASE("Enclave record")
{
  ringbuffer::Circuit eio_leader(1024);
  std::unique_ptr<WFactory> writer_factory_leader =
    std::make_unique<WFactory>(eio_leader);

  ringbuffer::Circuit eio_follower(1024);
  std::unique_ptr<WFactory> writer_factory_follower =
    std::make_unique<WFactory>(eio_follower);

  auto leader_ledger_enclave = LedgerEnclave(*writer_factory_leader);
  auto follower_ledger_enclave = LedgerEnclave(*writer_factory_follower);

  const std::vector<uint8_t> tx = {'a', 'b', 'c'};
  leader_ledger_enclave.put_entry(tx);
  size_t num_msgs = 0;
  std::vector<uint8_t> record;
  eio_leader.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case consensus::ledger_append:
        {
          REQUIRE(num_msgs == 0);
          copy(data, data + size, back_inserter(record));
        }
        break;
        default:
          REQUIRE(false);
      }
      ++num_msgs;
    });
  REQUIRE(num_msgs == 1);

  std::vector<uint8_t> msg(sizeof(uint32_t), 0);
  uint8_t* data_ = msg.data();
  size_t size = msg.size();
  serialized::write(data_, size, static_cast<uint32_t>(record.size()));
  copy(record.begin(), record.end(), back_inserter(msg));

  const uint8_t* data__ = msg.data();
  auto size_ = msg.size();

  num_msgs = 0;
  auto r = follower_ledger_enclave.record_entry(data__, size_);

  REQUIRE(r.second);
  REQUIRE(r.first == tx);
  eio_follower.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case consensus::ledger_append:
        {
          REQUIRE(num_msgs == 0);
          auto entry = std::vector<uint8_t>(data, data + size);
          REQUIRE(entry == tx);
        }
        break;
        default:
          REQUIRE(false);
      }
      ++num_msgs;
    });
  REQUIRE(num_msgs == 1);
}