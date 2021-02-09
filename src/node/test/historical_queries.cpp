// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/historical_queries.h"

#include "ds/messaging.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/history.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

using NumToString = kv::Map<size_t, std::string>;

struct StubWriter : public ringbuffer::AbstractWriter
{
public:
  struct Write
  {
    ringbuffer::Message m;
    bool finished;
    std::vector<uint8_t> contents;
  };
  std::mutex writes_mutex;
  std::vector<Write> writes;

  Write& get_write(const WriteMarker& marker)
  {
    REQUIRE(marker.has_value());
    REQUIRE(marker.value() < writes.size());
    return writes[marker.value()];
  }

  WriteMarker prepare(
    ringbuffer::Message m,
    size_t size,
    bool wait = true,
    size_t* identifier = nullptr) override
  {
    std::lock_guard<std::mutex> guard(writes_mutex);
    const auto index = writes.size();
    writes.push_back(Write{m, false, {}});
    return index;
  }

  void finish(const WriteMarker& marker) override
  {
    std::lock_guard<std::mutex> guard(writes_mutex);
    get_write(marker).finished = true;
  }

  WriteMarker write_bytes(
    const WriteMarker& marker, const uint8_t* bytes, size_t size) override
  {
    std::lock_guard<std::mutex> guard(writes_mutex);
    auto& write = get_write(marker);
    write.contents.insert(write.contents.end(), bytes, bytes + size);
    return marker;
  }
};

struct TestState
{
  std::shared_ptr<kv::Store> kv_store = nullptr;
  tls::KeyPairPtr kp = nullptr;
};

TestState create_and_init_state()
{
  TestState ts;

  ts.kv_store =
    std::make_shared<kv::Store>(std::make_shared<kv::StubConsensus>());
  ts.kv_store->set_encryptor(std::make_shared<kv::NullTxEncryptor>());

  ts.kp = tls::make_key_pair();

  // Make history to produce signatures
  const auto node_id = 0;
  ts.kv_store->set_history(
    std::make_shared<ccf::MerkleTxHistory>(*ts.kv_store, node_id, *ts.kp));

  {
    INFO("Store the signing node's key");
    auto tx = ts.kv_store->create_tx();
    auto nodes = tx.rw<ccf::Nodes>(ccf::Tables::NODES);
    ccf::NodeInfo ni;
    ni.cert = ts.kp->self_sign("CN=Test node");
    ni.status = ccf::NodeStatus::TRUSTED;
    nodes->put(node_id, ni);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  return ts;
}

kv::Version write_transactions_and_signature(
  kv::Store& kv_store, size_t tx_count)
{
  const auto begin = kv_store.current_version();
  const auto end = begin + tx_count;
  for (size_t i = begin; i < end; ++i)
  {
    auto tx = kv_store.create_tx();
    auto public_map = tx.rw<NumToString>("public:data");
    auto private_map = tx.rw<NumToString>("data");
    const auto s = std::to_string(i);
    public_map->put(i, s);
    private_map->put(i, s);

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  kv_store.get_history()->emit_signature();
  kv_store.compact(kv_store.current_version());

  return kv_store.current_version();
}

void validate_business_transaction(
  ccf::historical::StorePtr store, consensus::Index idx)
{
  REQUIRE(store != nullptr);

  auto tx = store->create_read_only_tx();
  auto public_map = tx.ro<NumToString>("public:data");
  auto private_map = tx.ro<NumToString>("data");

  const auto k = idx - 1;
  const auto v = std::to_string(k);

  auto public_v = public_map->get(k);
  REQUIRE(public_v.has_value());
  REQUIRE(*public_v == v);

  auto private_v = private_map->get(k);
  REQUIRE(private_v.has_value());
  REQUIRE(*private_v == v);

  size_t public_count = 0;
  public_map->foreach([&public_count](const auto& k, const auto& v) {
    REQUIRE(public_count++ == 0);
    return true;
  });

  size_t private_count = 0;
  private_map->foreach([&private_count](const auto& k, const auto& v) {
    REQUIRE(private_count++ == 0);
    return true;
  });
}

std::map<consensus::Index, std::vector<uint8_t>> construct_host_ledger(
  std::shared_ptr<kv::Consensus> c)
{
  auto consensus = dynamic_cast<kv::StubConsensus*>(c.get());
  REQUIRE(consensus != nullptr);

  INFO("Rebuild ledger as seen by host");
  std::map<consensus::Index, std::vector<uint8_t>> ledger;

  auto next_ledger_entry = consensus->pop_oldest_entry();
  while (next_ledger_entry.has_value())
  {
    const auto ib = ledger.insert(std::make_pair(
      std::get<0>(next_ledger_entry.value()),
      *std::get<1>(next_ledger_entry.value())));
    REQUIRE(ib.second);
    next_ledger_entry = consensus->pop_oldest_entry();
  }

  return ledger;
}

TEST_CASE("StateCache point queries")
{
  auto state = create_and_init_state();
  auto& kv_store = *state.kv_store;

  kv::Version low_signature_transaction;
  kv::Version high_signature_transaction;

  {
    INFO("Build some interesting state in the store");
    low_signature_transaction = write_transactions_and_signature(kv_store, 3);
    high_signature_transaction = write_transactions_and_signature(kv_store, 20);
    REQUIRE(kv_store.current_version() == high_signature_transaction);
  }

  size_t low_index = low_signature_transaction + 2;
  size_t high_index = high_signature_transaction - 3;
  size_t unsigned_index = high_signature_transaction + 5;

  auto ledger = construct_host_ledger(state.kv_store->get_consensus());
  REQUIRE(ledger.size() == high_signature_transaction);

  // Now we actually get to the historical queries
  auto stub_writer = std::make_shared<StubWriter>();
  ccf::historical::StateCache cache(kv_store, stub_writer);

  static const ccf::historical::RequestHandle default_handle = 0;
  static const ccf::historical::RequestHandle low_handle = 1;
  static const ccf::historical::RequestHandle high_handle = 2;

  {
    INFO(
      "Initially, no stores are available, even if they're requested multiple "
      "times");
    REQUIRE(cache.get_store_at(low_handle, low_index) == nullptr);
    REQUIRE(cache.get_store_at(low_handle, low_index) == nullptr);
    REQUIRE(cache.get_store_at(high_handle, high_index) == nullptr);
    REQUIRE(cache.get_store_at(low_handle, low_index) == nullptr);
    REQUIRE(cache.get_store_at(default_handle, unsigned_index) == nullptr);
    REQUIRE(cache.get_store_at(high_handle, high_index) == nullptr);
    REQUIRE(cache.get_store_at(low_handle, low_index) == nullptr);
  }

  {
    INFO("The host sees requests for these indices");
    REQUIRE(!stub_writer->writes.empty());
    std::set<consensus::Index> expected{low_index, high_index, unsigned_index};
    std::set<consensus::Index> actual;
    for (const auto& write : stub_writer->writes)
    {
      const uint8_t* data = write.contents.data();
      size_t size = write.contents.size();
      auto [idx, purpose] =
        ringbuffer::read_message<consensus::ledger_get>(data, size);
      REQUIRE(purpose == consensus::LedgerRequestPurpose::HistoricalQuery);
      actual.insert(idx);
    }
    REQUIRE(actual == expected);
  }

  auto provide_ledger_entry = [&](size_t i) {
    bool accepted = cache.handle_ledger_entry(i, ledger.at(i));
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
      REQUIRE(cache.get_store_at(high_handle, high_index) == nullptr);
    }

    REQUIRE(provide_ledger_entry(high_signature_transaction));
    REQUIRE(cache.get_store_at(high_handle, high_index) != nullptr);
  }

  {
    INFO(
      "Cache accepts _wrong_ requested entry, and the range of supporting "
      "entries");
    // NB: This is _a_ valid entry, but not at this index. In fact this stage
    // will accept anything that looks quite like a valid entry, even if it
    // never came from a legitimate node - they should all fail at the signature
    // check
    REQUIRE(cache.get_store_at(low_handle, low_index) == nullptr);
    REQUIRE(cache.handle_ledger_entry(low_index, ledger.at(low_index + 1)));

    // Count up to next signature
    for (size_t i = low_index + 1; i < high_signature_transaction; ++i)
    {
      REQUIRE(provide_ledger_entry(i));
      REQUIRE(cache.get_store_at(low_handle, low_index) == nullptr);
    }

    // Signature is good
    REQUIRE(provide_ledger_entry(high_signature_transaction));
    // Junk entry is still not available
    REQUIRE(cache.get_store_at(low_handle, low_index) == nullptr);
  }

  {
    INFO("Historical state can be retrieved from provided entries");
    auto store_at_index = cache.get_store_at(high_handle, high_index);
    REQUIRE(store_at_index != nullptr);

    validate_business_transaction(store_at_index, high_index);
  }

  {
    INFO("Cache doesn't throw when given junk");
    REQUIRE(cache.get_store_at(default_handle, unsigned_index) == nullptr);
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

  {
    INFO("Signature transactions can be requested");
    for (const auto i : {low_signature_transaction, high_signature_transaction})
    {
      auto store_at_index = cache.get_store_at(default_handle, i);
      REQUIRE(store_at_index == nullptr);

      REQUIRE(provide_ledger_entry(i));

      store_at_index = cache.get_store_at(default_handle, i);
      REQUIRE(store_at_index != nullptr);
    }

    {
      INFO("Store remains available for future requests using the same handle");
      const auto store1 =
        cache.get_store_at(default_handle, high_signature_transaction);
      REQUIRE(store1 != nullptr);

      const auto store2 =
        cache.get_store_at(default_handle, high_signature_transaction);
      REQUIRE(store2 == store1);
    }

    {
      INFO("Dropping a handle deletes it, and it can no longer be retrieved");
      cache.drop_request(default_handle);
      const auto store =
        cache.get_store_at(default_handle, high_signature_transaction);
      REQUIRE(store == nullptr);
    }

    {
      INFO("Handles are dropped automatically after their expiry duration");

      // Initial requests - low uses default expiry while high gets custom
      // expiry
      cache.set_default_expiry_duration(std::chrono::seconds(60));
      cache.get_store_at(low_handle, low_signature_transaction);
      cache.get_store_at(
        high_handle, high_signature_transaction, std::chrono::seconds(30));

      REQUIRE(provide_ledger_entry(low_signature_transaction));
      REQUIRE(provide_ledger_entry(high_signature_transaction));

      // NB: Calling get_store_at always resets the expiry time, so it must be
      // passed on each retrieval attempt

      // No time has passed, both are available
      REQUIRE(
        cache.get_store_at(low_handle, low_signature_transaction) != nullptr);
      REQUIRE(
        cache.get_store_at(
          high_handle, high_signature_transaction, std::chrono::seconds(30)) !=
        nullptr);

      // Some time passes, but not enough for either expiry
      cache.tick(std::chrono::milliseconds(20'000));
      REQUIRE(
        cache.get_store_at(low_handle, low_signature_transaction) != nullptr);
      REQUIRE(
        cache.get_store_at(
          high_handle, high_signature_transaction, std::chrono::seconds(30)) !=
        nullptr);

      // More time passes, and one request expires
      cache.tick(std::chrono::milliseconds(40'000));
      REQUIRE(
        cache.get_store_at(low_handle, low_signature_transaction) != nullptr);
      REQUIRE(
        cache.get_store_at(
          high_handle, high_signature_transaction, std::chrono::seconds(30)) ==
        nullptr);

      // More time passes, and both requests expire
      cache.tick(std::chrono::milliseconds(60'000));
      REQUIRE(
        cache.get_store_at(low_handle, low_signature_transaction) == nullptr);
      REQUIRE(
        cache.get_store_at(
          high_handle, high_signature_transaction, std::chrono::seconds(30)) ==
        nullptr);
    }
  }
}

TEST_CASE("StateCache range queries")
{
  auto state = create_and_init_state();
  auto& kv_store = *state.kv_store;
  const auto default_handle = 0;

  std::vector<kv::Version> signature_versions;

  const auto begin_index = kv_store.current_version() + 1;

  {
    INFO("Build some interesting state in the store");
    for (size_t batch_size : {10, 5, 2, 20, 5})
    {
      signature_versions.push_back(
        write_transactions_and_signature(kv_store, batch_size));
    }
  }

  const auto end_index = kv_store.current_version();

  ccf::historical::StateCache cache(kv_store, std::make_shared<StubWriter>());
  auto ledger = construct_host_ledger(state.kv_store->get_consensus());

  auto provide_ledger_entry = [&](size_t i) {
    bool accepted = cache.handle_ledger_entry(i, ledger.at(i));
    return accepted;
  };

  auto signing_version = [&signature_versions](kv::Version idx) {
    const auto begin = signature_versions.begin();
    const auto end = signature_versions.end();

    const auto exact_it = std::find(begin, end, idx);
    if (exact_it != end)
    {
      return idx;
    }

    const auto next_sig_it = std::upper_bound(begin, end, idx);
    REQUIRE(next_sig_it != end);
    return *next_sig_it;
  };

  auto fetch_and_validate_range =
    [&](kv::Version range_start, kv::Version range_end) {
      {
        auto stores =
          cache.get_store_range(default_handle, range_start, range_end);
        REQUIRE(stores.empty());
      }

      const auto proof_end = signing_version(range_end);
      for (auto i = range_start; i <= proof_end; ++i)
      {
        REQUIRE(provide_ledger_entry(i));
      }

      {
        auto stores =
          cache.get_store_range(default_handle, range_start, range_end);

        const auto range_size = (range_end - range_start) + 1;
        REQUIRE(stores.size() == range_size);
        for (size_t i = 0; i < stores.size(); ++i)
        {
          auto& store = stores[i];
          REQUIRE(store != nullptr);
          const auto idx = range_start + i;

          // Don't validate anything about signature transactions, just the
          // business transactions between them
          if (
            std::find(
              signature_versions.begin(), signature_versions.end(), idx) ==
            signature_versions.end())
          {
            validate_business_transaction(store, idx);
          }
        }
      }
    };

  {
    INFO("Fetch a single explicit range");
    const auto range_start = 4;
    const auto range_end = 7;

    fetch_and_validate_range(range_start, range_end);
  }

  {
    INFO("Fetch ranges of various sizes, including across multiple signatures");
    const size_t whole_range = end_index - begin_index;
    std::vector<size_t> range_sizes{3, 8, whole_range / 2, whole_range};
    for (const size_t range_size : range_sizes)
    {
      for (auto range_start = begin_index;
           range_start <= (end_index - range_size);
           ++range_start)
      {
        const auto range_end = range_start + range_size;
        fetch_and_validate_range(range_start, range_end);
      }
    }
  }
}

TEST_CASE("StateCache concurrent access")
{
  auto state = create_and_init_state();
  auto& kv_store = *state.kv_store;
  const auto default_handle = 0;

  std::vector<kv::Version> signature_versions;

  const auto begin_index = kv_store.current_version() + 1;

  {
    INFO("Build some interesting state in the store");
    for (size_t batch_size : {20, 10, 20})
    {
      signature_versions.push_back(
        write_transactions_and_signature(kv_store, batch_size));
    }
  }

  const auto end_index = kv_store.current_version();

  auto random_index = [&]() {
    return begin_index + (rand() % (end_index - begin_index - 1));
  };

  auto writer = std::make_shared<StubWriter>();
  ccf::historical::StateCache cache(kv_store, writer);

  std::atomic<bool> finished = false;
  std::thread host_thread([&]() {
    auto ledger = construct_host_ledger(state.kv_store->get_consensus());

    size_t last_handled_write = 0;
    while (!finished)
    {
      std::vector<StubWriter::Write> writes;
      {
        std::lock_guard<std::mutex> guard(writer->writes_mutex);
        writes.insert(
          writes.end(),
          writer->writes.begin() + last_handled_write,
          writer->writes.end());
        last_handled_write = writer->writes.size();
      }

      for (const auto& write : writes)
      {
        auto data = write.contents.data();
        auto size = write.contents.size();
        const auto [idx, purpose] =
          ringbuffer::read_message<consensus::ledger_get>(data, size);
        REQUIRE(purpose == consensus::LedgerRequestPurpose::HistoricalQuery);

        const auto it = ledger.find(idx);
        REQUIRE(it != ledger.end());
        cache.handle_ledger_entry(idx, it->second);
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  });

  auto query_random = [&](size_t handle) {
    for (size_t i = 0; i < 10; ++i)
    {
      const auto target_idx = random_index();

      ccf::historical::StorePtr store;
      // Poll to fetch point query
      while (true)
      {
        store = cache.get_store_at(handle, target_idx);
        if (store != nullptr)
        {
          break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }

      validate_business_transaction(store, target_idx);
    }
  };

  std::atomic<size_t> next_handle = 0;
  std::vector<std::thread> random_queries;
  for (size_t i = 0; i < 1; ++i)
  {
    random_queries.emplace_back(query_random, ++next_handle);
  }

  for (auto& thread : random_queries)
  {
    thread.join();
  }

  finished = true;
  host_thread.join();
}