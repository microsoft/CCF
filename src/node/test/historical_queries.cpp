// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/historical_queries.h"

#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/history.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

struct StubWriter : public ringbuffer::AbstractWriter
{
public:
  struct Write
  {
    ringbuffer::Message m;
    bool finished;
    std::vector<uint8_t> contents;
  };
  std::vector<Write> writes;

  Write& get_write(const WriteMarker& marker)
  {
    REQUIRE(marker.has_value());
    REQUIRE(marker.value() < writes.size());
    return writes[marker.value()];
  }

  Write& get_last_message()
  {
    REQUIRE(writes.size() > 0);
    auto& write = writes.back();
    REQUIRE(write.finished);
    return write;
  }

  WriteMarker prepare(
    ringbuffer::Message m,
    size_t size,
    bool wait = true,
    size_t* identifier = nullptr) override
  {
    const auto index = writes.size();
    writes.push_back(Write{m, false, {}});
    return index;
  }

  void finish(const WriteMarker& marker) override
  {
    get_write(marker).finished = true;
  }

  WriteMarker write_bytes(
    const WriteMarker& marker, const uint8_t* bytes, size_t size) override
  {
    auto& write = get_write(marker);
    write.contents.insert(write.contents.end(), bytes, bytes + size);
    return marker;
  }
};

TEST_CASE("StateCache")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  auto consensus = std::make_shared<kv::StubConsensus>();

  kv::Store store(consensus);
  store.set_encryptor(encryptor);

  // Make history to produce signatures
  auto& signatures = store.create<ccf::Signatures>(
    ccf::Tables::SIGNATURES, kv::SecurityDomain::PUBLIC);
  auto& nodes =
    store.create<ccf::Nodes>(ccf::Tables::NODES, kv::SecurityDomain::PUBLIC);

  auto kp = tls::make_key_pair();
  auto history =
    std::make_shared<ccf::MerkleTxHistory>(store, 0, *kp, signatures, nodes);

  store.set_history(history);

  {
    INFO("Build some interesting state in the store");
    auto& as_string = store.create<kv::Map<size_t, std::string>>("as_string");
    auto& even = store.create<kv::Map<std::string, bool>>("even");

    {
      for (size_t i = 0; i < 20; ++i)
      {
        kv::Tx tx;
        auto view = tx.get_view(as_string);
        const auto s = std::to_string(i);
        view->put(i, s);

        if (i % 3 == 0)
        {
          auto view1 = tx.get_view(even);
          view1->put(s, s.size() % 2 == 0);
        }

        REQUIRE(tx.commit() == kv::CommitSuccess::OK);
      }
    }

    store.compact(store.current_version());
  }

  auto stub_writer = std::make_shared<StubWriter>();
  ccf::historical::StateCache cache(store, stub_writer);

  const auto store_at_10 = cache.get_store_at(10);
  REQUIRE(store_at_10 == nullptr);

  auto& last_message_written = stub_writer->get_last_message();
  // TODO: Build a dummy dispatcher which will respond with ledger entries?

  std::vector<std::vector<uint8_t>> ledger;
  auto ledger_entry_pair = consensus->pop_oldest_data();
  while (ledger_entry_pair.second)
  {
    ledger.push_back(ledger_entry_pair.first);
    ledger_entry_pair = consensus->pop_oldest_data();
  }

  REQUIRE(ledger.size() == 20);
}