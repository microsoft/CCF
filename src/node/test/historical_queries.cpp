// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/historical_queries.h"

#include "ds/messaging.h"
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
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    store, node_id, *kp, signatures, nodes);

  store.set_history(history);

  using NumToString = kv::Map<size_t, std::string>;

  constexpr size_t low_signature_transaction = 3;
  constexpr size_t high_signature_transaction = 100;

  constexpr size_t low_index = low_signature_transaction + 2;
  constexpr size_t high_index = high_signature_transaction - 3;
  constexpr size_t unsigned_index = high_signature_transaction + 5;

  {
    INFO("Build some interesting state in the store");

    {
      INFO("Store the signing node's key");
      auto tx = store.create_tx();
      auto view = tx.get_view(nodes);
      ccf::NodeInfo ni;
      ni.cert = kp->self_sign("CN=Test node");
      ni.status = ccf::NodeStatus::TRUSTED;
      view->put(node_id, ni);
      REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    }

    auto& public_table =
      store.create<NumToString>("public", kv::SecurityDomain::PUBLIC);
    auto& private_table =
      store.create<NumToString>("private", kv::SecurityDomain::PRIVATE);

    {
      for (size_t i = 1; i < high_signature_transaction; ++i)
      {
        if (
          i == low_signature_transaction - 1 ||
          i == high_signature_transaction - 1)
        {
          history->emit_signature();
          store.compact(store.current_version());
        }
        else
        {
          auto tx = store.create_tx();
          auto [public_view, private_view] =
            tx.get_view(public_table, private_table);
          const auto s = std::to_string(i);
          public_view->put(i, s);
          private_view->put(i, s);

          REQUIRE(tx.commit() == kv::CommitSuccess::OK);
        }
      }
    }

    REQUIRE(store.current_version() == high_signature_transaction);
  }

  std::map<consensus::Index, std::vector<uint8_t>> ledger;
  {
    INFO("Rebuild ledger as seen by host");
    auto next_ledger_entry = consensus->pop_oldest_entry();
    while (next_ledger_entry.has_value())
    {
      const auto ib = ledger.insert(std::make_pair(
        std::get<0>(next_ledger_entry.value()),
        *std::get<1>(next_ledger_entry.value())));
      REQUIRE(ib.second);
      next_ledger_entry = consensus->pop_oldest_entry();
    }

    REQUIRE(ledger.size() == high_signature_transaction);
  }

  // Now we actually get to the historical queries
  std::vector<consensus::Index> requested_ledger_entries = {};
  messaging::BufferProcessor bp("historical_queries");
  DISPATCHER_SET_MESSAGE_HANDLER(
    bp,
    consensus::ledger_get,
    [&requested_ledger_entries](const uint8_t* data, size_t size) {
      auto [idx, purpose] =
        ringbuffer::read_message<consensus::ledger_get>(data, size);
      REQUIRE(purpose == consensus::LedgerRequestPurpose::HistoricalQuery);
      requested_ledger_entries.push_back(idx);
    });

  constexpr size_t buffer_size = 1 << 12;

  ringbuffer::Reader rr(buffer_size);
  auto rw = std::make_shared<ringbuffer::Writer>(rr);
  ccf::historical::StateCache cache(store, rw);

  {
    INFO(
      "Initially, no stores are available, even if they're requested multiple "
      "times");
    REQUIRE(cache.get_store_at(low_index) == nullptr);
    REQUIRE(cache.get_store_at(low_index) == nullptr);
    REQUIRE(cache.get_store_at(high_index) == nullptr);
    REQUIRE(cache.get_store_at(low_index) == nullptr);
    REQUIRE(cache.get_store_at(unsigned_index) == nullptr);
    REQUIRE(cache.get_store_at(high_index) == nullptr);
    REQUIRE(cache.get_store_at(low_index) == nullptr);
  }

  {
    INFO("The host sees one request for each index");
    const auto read = bp.read_n(100, rr);
    REQUIRE(read == 3);
    REQUIRE(requested_ledger_entries.size() == 3);
    REQUIRE(
      requested_ledger_entries ==
      std::vector<consensus::Index>{low_index, high_index, unsigned_index});
  }

  auto provide_ledger_entry = [&](size_t i) {
    bool accepted = cache.handle_ledger_entry(i, ledger.at(i));
    // Pump outbound ringbuffer to clear messages
    bp.read_n(100, rr);
    return accepted;
  };

  {
    INFO("Cache doesn't accept arbitrary entries");
    REQUIRE(!provide_ledger_entry(high_index - 1));
    REQUIRE(!provide_ledger_entry(high_index + 1));
  }

  {
    INFO(
      "Cache accepts requested entries, and then range of supporting entries");
    REQUIRE(provide_ledger_entry(high_index));

    // Count up to next signature
    for (size_t i = high_index + 1; i < high_signature_transaction; ++i)
    {
      REQUIRE(provide_ledger_entry(i));
      REQUIRE(cache.get_store_at(high_index) == nullptr);
    }

    REQUIRE(provide_ledger_entry(high_signature_transaction));
    REQUIRE(cache.get_store_at(high_index) != nullptr);
  }

  {
    INFO(
      "Cache accepts _wrong_ requested entry, and the range of supporting "
      "entries");
    // NB: This is _a_ valid entry, but not at this index. In fact this stage
    // will accept anything that looks quite like a valid entry, even if it
    // never came from a legitimate node - they should all fail at the signature
    // check
    REQUIRE(cache.get_store_at(low_index) == nullptr);
    REQUIRE(cache.handle_ledger_entry(low_index, ledger.at(low_index + 1)));

    // Count up to next signature
    for (size_t i = low_index + 1; i < high_signature_transaction; ++i)
    {
      REQUIRE(provide_ledger_entry(i));
      REQUIRE(cache.get_store_at(low_index) == nullptr);
    }

    // Signature is good
    REQUIRE(provide_ledger_entry(high_signature_transaction));
    // Junk entry is still not available
    REQUIRE(cache.get_store_at(low_index) == nullptr);
  }

  {
    INFO("Historical state can be retrieved from provided entries");
    auto store_at_index = cache.get_store_at(high_index);
    REQUIRE(store_at_index != nullptr);

    {
      auto& public_table = *store_at_index->get<NumToString>("public");
      auto& private_table = *store_at_index->get<NumToString>("private");

      auto tx = store_at_index->create_tx();
      auto [public_view, private_view] =
        tx.get_view(public_table, private_table);

      const auto k = high_index - 1;
      const auto v = std::to_string(k);

      auto public_v = public_view->get(k);
      REQUIRE(public_v.has_value());
      REQUIRE(*public_v == v);

      auto private_v = private_view->get(k);
      REQUIRE(private_v.has_value());
      REQUIRE(*private_v == v);

      size_t public_count = 0;
      public_view->foreach([&public_count](const auto& k, const auto& v) {
        REQUIRE(public_count++ == 0);
        return true;
      });

      size_t private_count = 0;
      private_view->foreach([&private_count](const auto& k, const auto& v) {
        REQUIRE(private_count++ == 0);
        return true;
      });
    }
  }

  {
    INFO("Cache doesn't throw when given junk");
    REQUIRE(cache.get_store_at(unsigned_index) == nullptr);
    bool result;
    REQUIRE_NOTHROW(result = cache.handle_ledger_entry(unsigned_index, {}));
    REQUIRE(!result);
    REQUIRE_NOTHROW(
      result = cache.handle_ledger_entry(unsigned_index, {0x1, 0x2, 0x3}));
    REQUIRE(!result);
    REQUIRE_NOTHROW(
      result = cache.handle_ledger_entry(unsigned_index, ledger[low_index]));
    REQUIRE(!result);
    REQUIRE_NOTHROW(
      result = cache.handle_ledger_entry(
        unsigned_index, ledger[high_signature_transaction]));
    REQUIRE(!result);
  }
}