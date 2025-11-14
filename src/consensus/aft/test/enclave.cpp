// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "consensus/ledger_enclave.h"
#include "ds/ring_buffer.h"

#include <doctest/doctest.h>

#undef FAIL

using namespace consensus;

using WFactory = ringbuffer::WriterFactory;

TEST_CASE("Enclave put")
{
  constexpr auto buffer_size = 1024;
  auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Circuit eio(in_buffer->bd, out_buffer->bd);
  std::unique_ptr<WFactory> writer_factory = std::make_unique<WFactory>(eio);

  auto enclave = LedgerEnclave(*writer_factory);

  bool globally_committable = false;
  const std::vector<uint8_t> tx = {'a', 'b', 'c'};
  enclave.put_entry(tx, globally_committable, 1, 1);
  size_t num_msgs = 0;
  eio.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case ::consensus::ledger_append:
        {
          REQUIRE(num_msgs == 0);
          REQUIRE(serialized::read<bool>(data, size) == globally_committable);
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
  constexpr auto buffer_size_leader = 1024;
  auto in_buffer_leader =
    std::make_unique<ringbuffer::TestBuffer>(buffer_size_leader);
  auto out_buffer_leader =
    std::make_unique<ringbuffer::TestBuffer>(buffer_size_leader);
  ringbuffer::Circuit eio_leader(in_buffer_leader->bd, out_buffer_leader->bd);
  std::unique_ptr<WFactory> writer_factory_leader =
    std::make_unique<WFactory>(eio_leader);

  constexpr auto buffer_size_follower = 1024;
  auto in_buffer_follower =
    std::make_unique<ringbuffer::TestBuffer>(buffer_size_follower);
  auto out_buffer_follower =
    std::make_unique<ringbuffer::TestBuffer>(buffer_size_follower);
  ringbuffer::Circuit eio_follower(
    in_buffer_follower->bd, out_buffer_follower->bd);
  std::unique_ptr<WFactory> writer_factory_follower =
    std::make_unique<WFactory>(eio_follower);

  auto leader_ledger_enclave = LedgerEnclave(*writer_factory_leader);
  auto follower_ledger_enclave = LedgerEnclave(*writer_factory_follower);

  bool globally_committable = false;
  const std::vector<uint8_t> entry = {'a', 'b', 'c'};
  ccf::kv::SerialisedEntryHeader entry_header;

  std::vector<uint8_t> tx(ccf::kv::serialised_entry_header_size + entry.size());
  auto tx_ = tx.data();
  auto size_ = tx.size();
  serialized::write(tx_, size_, entry_header);
  serialized::write(tx_, size_, entry.data(), entry.size());

  leader_ledger_enclave.put_entry(tx, globally_committable, 1, 1);
  size_t num_msgs = 0;
  std::vector<uint8_t> record;
  eio_leader.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case ::consensus::ledger_append:
        {
          REQUIRE(num_msgs == 0);
          REQUIRE(serialized::read<bool>(data, size) == globally_committable);
          copy(data, data + size, back_inserter(record));
        }
        break;
        default:
          REQUIRE(false);
      }
      ++num_msgs;
    });
  REQUIRE(num_msgs == 1);
  REQUIRE(record == tx);

  num_msgs = 0;
  follower_ledger_enclave.put_entry(record, globally_committable, 1, 2);
  eio_follower.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case ::consensus::ledger_append:
        {
          REQUIRE(num_msgs == 0);
          REQUIRE(serialized::read<bool>(data, size) == globally_committable);
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