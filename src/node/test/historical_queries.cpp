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

  const auto node_id = 0;

  auto kp = tls::make_key_pair();
  auto history =
    std::make_shared<ccf::MerkleTxHistory>(store, node_id, *kp, signatures, nodes);

  store.set_history(history);

  using NumToString = kv::Map<size_t, std::string>;
  using StringToBool = kv::Map<std::string, bool>;

  {
    INFO("Build some interesting state in the store");

    {
      INFO("Store the signing node's key");
      kv::Tx tx;
      auto view = tx.get_view(nodes);
      ccf::NodeInfo ni;
      ni.cert = kp->self_sign("CN=Test node");
      ni.status = ccf::NodeStatus::TRUSTED;
      view->put(node_id, ni);
      REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    }

    auto& as_string = store.create<NumToString>("as_string");
    auto& even = store.create<StringToBool>("even");

    {
      for (size_t i = 1; i < 20; ++i)
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

    history->emit_signature();

    store.compact(store.current_version());
  }

  std::vector<std::vector<uint8_t>> ledger;
  auto ledger_entry_pair = consensus->pop_oldest_data();
  while (ledger_entry_pair.second)
  {
    ledger.push_back(ledger_entry_pair.first);
    ledger_entry_pair = consensus->pop_oldest_data();
  }

  REQUIRE(ledger.size() == 21);

  // Now we actually get to the historical query part
  auto stub_writer = std::make_shared<StubWriter>();
  ccf::historical::StateCache cache(store, stub_writer);

  {
    auto store_at_10 = cache.get_store_at(10);
    REQUIRE(store_at_10 == nullptr);
  }

  auto& last_message_written = stub_writer->get_last_message();
  // TODO: Build a dummy dispatcher which will respond with ledger entries?

  // TODO: Change stub consensus to store indices, so we don't have this manual
  // off-by-one correction?

  // Cache doesn't accept arbitrary entries
  REQUIRE(!cache.handle_ledger_entry(9, ledger[8]));
  REQUIRE(!cache.handle_ledger_entry(11, ledger[10]));

  // Cache accepts requested entries, and then subsequent entries to a signature
  for (size_t i = 10; i <= 20; ++i)
  {
    REQUIRE(cache.handle_ledger_entry(i, ledger[i - 1]));
    auto store_at_10 = cache.get_store_at(i);
    REQUIRE(store_at_10 == nullptr);
  }

  REQUIRE(cache.handle_ledger_entry(21, ledger[20]));
  auto store_at_10 = cache.get_store_at(10);
  REQUIRE(store_at_10 != nullptr);

  {
    auto& as_string = *store_at_10->get<NumToString>("as_string");
    auto& even = *store_at_10->get<StringToBool>("even");

    kv::Tx tx;
    auto [as_string_view, even_view] = tx.get_view(as_string, even);

    std::cout << "as_string writes at index 10:" << std::endl;
    as_string_view->foreach([](const auto& k, const auto& v) {
      std::cout << fmt::format("{}: {}", k, v) << std::endl;
      return true;
    });

    std::cout << "even writes at index 10:" << std::endl;
    even_view->foreach([](const auto& k, const auto& v) {
      std::cout << fmt::format("{}: {}", k, v) << std::endl;
      return true;
    });
  }
}