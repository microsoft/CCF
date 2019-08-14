// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../ledgerenclave.h"
#include "ds/ringbuffer.h"
#include "tls/keypair.h"

#include <doctest/doctest.h>

#undef FAIL

using namespace raft;

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
        case raft::log_append:
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
  ringbuffer::Circuit eio_primary(1024);
  std::unique_ptr<WFactory> writer_factory_primary =
    std::make_unique<WFactory>(eio_primary);

  ringbuffer::Circuit eio_backup(1024);
  std::unique_ptr<WFactory> writer_factory_backup =
    std::make_unique<WFactory>(eio_backup);

  auto primary_ledger_enclave = LedgerEnclave(*writer_factory_primary);
  auto backup_ledger_enclave = LedgerEnclave(*writer_factory_backup);

  const std::vector<uint8_t> tx = {'a', 'b', 'c'};
  primary_ledger_enclave.put_entry(tx);
  size_t num_msgs = 0;
  std::vector<uint8_t> record;
  eio_primary.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case raft::log_append:
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
  auto r = backup_ledger_enclave.record_entry(data__, size_);

  REQUIRE(r.second);
  REQUIRE(r.first == tx);
  eio_backup.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case raft::log_append:
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