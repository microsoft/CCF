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
  constexpr auto buffer_size = 1024;
  std::vector<uint8_t> in_buffer(buffer_size);
  ringbuffer::Const in_span(in_buffer.data(), in_buffer.size());
  std::vector<uint8_t> out_buffer(buffer_size);
  ringbuffer::Const out_span(out_buffer.data(), out_buffer.size());
  ringbuffer::Circuit eio(in_span, out_span);
  std::unique_ptr<WFactory> writer_factory = std::make_unique<WFactory>(eio);

  auto enclave = LedgerEnclave(*writer_factory);

  bool globally_committable = false;
  bool force_ledger_chunk = false;
  const std::vector<uint8_t> tx = {'a', 'b', 'c'};
  enclave.put_entry(tx, globally_committable, force_ledger_chunk);
  size_t num_msgs = 0;
  eio.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case consensus::ledger_append:
        {
          REQUIRE(num_msgs == 0);
          REQUIRE(serialized::read<bool>(data, size) == globally_committable);
          REQUIRE(serialized::read<bool>(data, size) == force_ledger_chunk);
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
  std::vector<uint8_t> in_buffer_leader(buffer_size_leader);
  ringbuffer::Const in_span_leader(
    in_buffer_leader.data(), in_buffer_leader.size());
  std::vector<uint8_t> out_buffer_leader(buffer_size_leader);
  ringbuffer::Const out_span_leader(
    out_buffer_leader.data(), out_buffer_leader.size());
  ringbuffer::Circuit eio_leader(in_span_leader, out_span_leader);
  std::unique_ptr<WFactory> writer_factory_leader =
    std::make_unique<WFactory>(eio_leader);

  constexpr auto buffer_size_follower = 1024;
  std::vector<uint8_t> in_buffer_follower(buffer_size_follower);
  ringbuffer::Const in_span_follower(
    in_buffer_follower.data(), in_buffer_follower.size());
  std::vector<uint8_t> out_buffer_follower(buffer_size_follower);
  ringbuffer::Const out_span_follower(
    out_buffer_follower.data(), out_buffer_follower.size());
  ringbuffer::Circuit eio_follower(in_span_follower, out_span_follower);
  std::unique_ptr<WFactory> writer_factory_follower =
    std::make_unique<WFactory>(eio_follower);

  auto leader_ledger_enclave = LedgerEnclave(*writer_factory_leader);
  auto follower_ledger_enclave = LedgerEnclave(*writer_factory_follower);

  bool globally_committable = false;
  bool force_ledger_chunk = false;
  const std::vector<uint8_t> tx = {'a', 'b', 'c'};
  leader_ledger_enclave.put_entry(tx, globally_committable, force_ledger_chunk);
  size_t num_msgs = 0;
  std::vector<uint8_t> record;
  eio_leader.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case consensus::ledger_append:
        {
          REQUIRE(num_msgs == 0);
          REQUIRE(serialized::read<bool>(data, size) == globally_committable);
          REQUIRE(serialized::read<bool>(data, size) == force_ledger_chunk);
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
  auto r = follower_ledger_enclave.get_entry(data__, size_);
  REQUIRE(r == tx);
  follower_ledger_enclave.put_entry(
    r, globally_committable, force_ledger_chunk);
  eio_follower.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case consensus::ledger_append:
        {
          REQUIRE(num_msgs == 0);
          REQUIRE(serialized::read<bool>(data, size) == globally_committable);
          REQUIRE(serialized::read<bool>(data, size) == force_ledger_chunk);
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