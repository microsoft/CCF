// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_paged.h"
#include "indexing/lfs_interface.h"
#include "indexing/test/common.h"

#include <deque>
#include <doctest/doctest.h>
#include <iostream>

namespace
{
  using namespace ccf::indexing;
  using ccf::SeqNoCollection;
  using Index = strategies::SeqnosByKey_Paged<decltype(map_a)>;

  class AsyncLFS : public AbstractLFSAccess
  {
  public:
    std::map<LFSKey, LFSContents> disk;
    std::deque<std::function<void()>> work;
    size_t peak_queue = 0;
    size_t peak_batch_bytes = 0;
    size_t stores = 0;
    LFSKey last_root;
    bool fail_batch = false;
    bool coalesce_loaded = false;
    FetchResultPtr coalesced;

    void enqueue(std::function<void()> fn)
    {
      work.push_back(std::move(fn));
      peak_queue = std::max(peak_queue, work.size());
    }

    void step()
    {
      if (!work.empty())
      {
        auto fn = std::move(work.front());
        work.pop_front();
        fn();
      }
    }

    void store(const LFSKey& key, LFSContents&& contents) override
    {
      enqueue([this, key, contents = std::move(contents)]() {
        disk[key] = contents;
      });
    }

    FetchResultPtr fetch(
      const LFSKey& key,
      size_t max_bytes = std::numeric_limits<size_t>::max()) override
    {
      if (coalesce_loaded && coalesced && coalesced->key == key)
        return coalesced;
      auto result = std::make_shared<FetchResult>();
      if (coalesce_loaded)
        coalesced = result;
      result->key = key;
      result->fetch_result = FetchResult::FetchResultType::Fetching;
      enqueue([this, result, max_bytes]() {
        auto it = disk.find(result->key);
        if (it == disk.end())
          result->fetch_result = FetchResult::FetchResultType::NotFound;
        else if (it->second.size() > max_bytes)
          result->fetch_result = FetchResult::FetchResultType::Corrupt;
        else
        {
          result->contents = it->second;
          result->fetch_result = FetchResult::FetchResultType::Loaded;
        }
      });
      return result;
    }

    LFSBatchResult apply_batch(
      LFSWrites&& writes, std::vector<LFSKey>&& removals) override
    {
      auto result =
        std::make_shared<std::atomic<LFSBatchStatus>>(LFSBatchStatus::Pending);
      size_t n = 0;
      for (const auto& [key, blob] : writes)
        n += blob.size();
      peak_batch_bytes = std::max(peak_batch_bytes, n);
      last_root = writes.back().first;
      enqueue([this,
               result,
               writes = std::move(writes),
               removals = std::move(removals)]() {
        if (fail_batch)
        {
          *result = LFSBatchStatus::Failed;
          return;
        }
        for (const auto& [key, blob] : writes)
        {
          disk[key] = blob;
          ++stores;
        }
        for (const auto& key : removals)
          disk.erase(key);
        *result = LFSBatchStatus::Complete;
      });
      return result;
    }
  };

  struct Fixture
  {
    std::shared_ptr<AsyncLFS> lfs = std::make_shared<AsyncLFS>();
    ccf::AbstractNodeContext context;
    std::shared_ptr<Index> index;
    size_t seqno = 0;
    const size_t page_bytes;

    Fixture(size_t cache = 0, size_t page = 512) : page_bytes(page)
    {
      context.install_subsystem(lfs);
      index = std::make_shared<Index>(map_a, context, page, cache);
    }

    void begin(const std::vector<std::string>& keys)
    {
      auto store = std::make_shared<ccf::kv::Store>();
      store->initialise_term(1);
      store->set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
      auto tx = store->create_tx();
      for (const auto& key : keys)
        tx.rw(map_a)->put(key, "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      index->handle_committed_transaction({1, ++seqno}, store);
    }

    void finish()
    {
      for (size_t i = 0; i < 100000; ++i)
      {
        if (index->get_indexed_watermark().seqno == seqno)
          return;
        lfs->step();
        index->tick();
      }
      FAIL("Paged update did not finish within bounded retries");
    }

    void add(const std::vector<std::string>& keys)
    {
      begin(keys);
      finish();
      flush();
      auto d = index->describe();
      CHECK(d["live_pages"] == lfs->disk.size());
      size_t n = 0;
      for (const auto& [key, blob] : lfs->disk)
      {
        CHECK(blob.size() <= page_bytes);
        n += blob.size();
      }
      CHECK(d["live_page_bytes"] == n);
    }

    void flush()
    {
      index->flush();
      for (size_t i = 0; i < 100000; ++i)
      {
        const auto d = index->describe();
        if (d["dirty_pages"] == 0 && d["pending_write_batch"] == false)
          return;
        lfs->step();
        index->tick();
      }
      FAIL("Paged checkpoint did not finish within bounded retries");
    }

    SeqNoCollection query(
      const std::string& key, ccf::SeqNo from, ccf::SeqNo to)
    {
      for (size_t i = 0; i < 100000; ++i)
      {
        auto result = index->get_write_txs_in_range(key, from, to);
        if (result)
          return *result;
        lfs->step();
        index->tick();
      }
      FAIL("Paged query did not finish within bounded retries");
      return {};
    }
  };
}

TEST_CASE(
  "Paged splits, sparse, hot and distinct keys" * doctest::test_suite("paged"))
{
  for (const size_t cache : {0, 512, 2048})
  {
    Fixture f(cache);
    ExpectedSeqNos hot;
    ExpectedSeqNos sparse;
    for (size_t i = 1; i <= 350; ++i)
    {
      std::vector<std::string> keys{"hot", fmt::format("key-{:04}", 351 - i)};
      hot.insert(i);
      if (i == 1 || i == 350)
      {
        keys.push_back("sparse");
        sparse.insert(i);
      }
      f.add(keys);
    }
    CHECK(f.index->describe()["height"].get<size_t>() >= 3);
    CHECK(check_seqnos(hot, f.query("hot", 0, f.seqno)));
    CHECK(check_seqnos(sparse, f.query("sparse", 0, f.seqno)));
    CHECK(check_seqnos({1, 2, 3}, f.query("hot", 1, 3)));
    CHECK(check_seqnos({350}, f.query("hot", 350, 350)));
    CHECK(check_seqnos({}, f.query("sparse", 2, 349)));
    CHECK(check_seqnos({}, f.query("missing", 0, f.seqno)));
    CHECK(check_seqnos({227}, f.query("key-0124", 0, f.seqno)));
    CHECK_FALSE(f.index->get_write_txs_in_range("hot", 0, 351));
    CHECK_THROWS_AS(
      f.index->get_write_txs_in_range("hot", 2, 1), std::invalid_argument);
    CHECK(f.index->describe()["cache_peak_bytes"].get<size_t>() <= cache);
    CHECK(f.lfs->peak_queue == 1);
    CHECK(f.lfs->stores > f.lfs->disk.size() * 5);
  }
}

TEST_CASE(
  "Paged async updates publish only complete transactions" *
  doctest::test_suite("paged"))
{
  Fixture f;
  f.add({"a", "b"});
  f.begin({"a", "b", "c"});
  CHECK(f.index->get_indexed_watermark().seqno == 1);
  CHECK_FALSE(f.index->next_requested());
  for (size_t i = 0; i < 10; ++i)
    f.index->tick();
  CHECK(f.index->get_indexed_watermark().seqno == 1);
  CHECK(f.lfs->work.size() == 1);
  CHECK_FALSE(f.index->get_write_txs_in_range("a", 0, 1));
  f.finish();
  CHECK(f.index->next_requested() == 3);
  CHECK(check_seqnos({1, 2}, f.query("a", 0, 2)));
  CHECK(check_seqnos({2}, f.query("c", 0, 2)));

  f.flush();
  CHECK_FALSE(f.index->get_write_txs_in_range("a", 0, 2));
  CHECK_FALSE(f.index->get_write_txs_in_range("different", 0, 2));
  f.begin({"a"});
  // An existing cursor owns the old root and can finish while a transaction
  // waits; no page it needs is reclaimed.
  CHECK(check_seqnos({1, 2}, f.query("a", 0, 2)));
  f.finish();
  CHECK(check_seqnos({1, 2, 3}, f.query("a", 0, 3)));
}

TEST_CASE(
  "Paged required pages cannot be removed or substituted" *
  doctest::test_suite("paged"))
{
  for (const std::string fault :
       {"missing",
        "corrupt",
        "substitute",
        "stale",
        "child",
        "child-corrupt",
        "child-substitute",
        "child-stale"})
  {
    CAPTURE(fault);
    Fixture f;
    f.add({"hot"});
    auto old_root = f.lfs->disk.at(f.lfs->last_root);
    for (size_t i = 0; i < 100; ++i)
      f.add({"hot", fmt::format("key-{}", i)});
    auto root = f.lfs->last_root;
    if (fault == "missing")
      f.lfs->disk.erase(root);
    else if (fault == "corrupt")
      f.lfs->disk[root][0] ^= 1;
    else if (fault == "stale")
      f.lfs->disk[root] = old_root;
    else if (fault.starts_with("child-"))
    {
      const auto hot = MapA::KeySerialiser::to_serialised("hot");
      auto leaf = std::find_if(
        f.lfs->disk.begin(), f.lfs->disk.end(), [&](const auto& item) {
          const auto& blob = item.second;
          return blob.front() == 1 &&
            std::search(blob.begin(), blob.end(), hot.begin(), hot.end()) !=
            blob.end();
        });
      REQUIRE(leaf != f.lfs->disk.end());
      if (fault == "child-corrupt")
        leaf->second.back() ^= 1;
      else if (fault == "child-stale")
        leaf->second = old_root;
      else
        leaf->second = f.lfs->disk.at(root);
    }
    else
    {
      auto other = f.lfs->disk.begin();
      while (other->first == root)
        ++other;
      if (fault == "child")
      {
        // All hot-key leaves are required by the full range. Remove every
        // non-root page, leaving an authentic root.
        for (auto it = f.lfs->disk.begin(); it != f.lfs->disk.end();)
          if (it->first != root)
            it = f.lfs->disk.erase(it);
          else
            ++it;
      }
      else
        f.lfs->disk[root] = other->second;
    }
    for (size_t i = 0; i < 200; ++i)
    {
      CHECK_FALSE(f.index->get_write_txs_in_range("hot", 0, f.seqno));
      f.lfs->step();
      f.index->tick();
    }
    CHECK(f.index->describe()["failed"] == true);
    CHECK_FALSE(f.index->next_requested());
  }
}

TEST_CASE(
  "Paged coalesced loaded results remain immutable" *
  doctest::test_suite("paged"))
{
  Fixture f;
  f.add({"a"});
  f.lfs->coalesce_loaded = true;
  CHECK(check_seqnos({1}, f.query("a", 0, 1)));
  REQUIRE(f.lfs->coalesced);
  CHECK_FALSE(f.lfs->coalesced->contents.empty());
  CHECK(check_seqnos({1}, f.query("a", 0, 1)));
  CHECK(f.index->describe()["failed"] == false);
}

TEST_CASE("Paged write failures stop progress" * doctest::test_suite("paged"))
{
  Fixture f;
  f.add({"a"});
  f.lfs->fail_batch = true;
  f.begin({"b"});
  f.finish();
  f.index->flush();
  for (size_t i = 0; i < 20; ++i)
  {
    f.lfs->step();
    f.index->tick();
  }
  CHECK(f.index->describe()["failed"] == true);
  CHECK(f.index->get_indexed_watermark().seqno == 2);
  CHECK_FALSE(f.index->get_write_txs_in_range("a", 0, 1));
  CHECK(f.lfs->work.empty());
}

TEST_CASE(
  "Paged query cancellation drains I/O before updating" *
  doctest::test_suite("paged"))
{
  Fixture f;
  f.add({"a"});
  CHECK_FALSE(f.index->get_write_txs_in_range("a", 0, 1));
  f.index->cancel_query();
  for (size_t i = 0; i < 10; ++i)
  {
    CHECK_FALSE(f.index->get_write_txs_in_range("b", 0, 1));
    f.index->cancel_query();
  }
  CHECK(f.lfs->work.size() == 1);
  f.begin({"a"});
  f.finish();
  CHECK(check_seqnos({1, 2}, f.query("a", 0, 2)));
  CHECK(f.lfs->peak_queue == 1);
}

TEST_CASE(
  "Paged mixed key lengths, multi-entry transactions and key limits" *
  doctest::test_suite("paged"))
{
  Fixture f(512);
  std::map<std::string, ExpectedSeqNos> model;
  for (size_t batch = 0; batch < 6; ++batch)
  {
    std::vector<std::string> keys;
    for (size_t i = 0; i < 120; ++i)
    {
      auto key = fmt::format("{:03}-", (i * 37 + batch * 13) % 120) +
        std::string(i % 40, 'x');
      keys.push_back(key);
      model[key].insert(batch + 1);
    }
    keys.push_back("");
    keys.push_back(std::string("a\0b", 3));
    model[""].insert(batch + 1);
    model[std::string("a\0b", 3)].insert(batch + 1);
    f.add(keys);
  }
  for (const auto& [key, expected] : model)
    CHECK(check_seqnos(expected, f.query(key, 0, f.seqno)));
  CHECK(f.lfs->peak_queue == 1);

  Fixture oversized;
  oversized.begin({std::string(512, 'x')});
  CHECK(oversized.index->describe()["failed"] == true);
  CHECK(oversized.index->get_indexed_watermark().seqno == 0);
  CHECK(oversized.lfs->work.empty());
  CHECK_THROWS_AS(Index("private:map", f.context), std::invalid_argument);
  CHECK_THROWS_AS(Index(map_a, f.context, 511), std::invalid_argument);
  ccf::AbstractNodeContext no_lfs;
  CHECK_THROWS_AS(Index(map_a, no_lfs), std::invalid_argument);
}

TEST_CASE(
  "Paged representative resource distributions" * doctest::test_suite("paged"))
{
  for (const auto distribution : {"hot", "sparse", "distinct"})
  {
    Fixture f(1024);
    size_t entries = 0;
    for (size_t i = 0; i < 1000; ++i)
    {
      std::vector<std::string> keys;
      if (std::string(distribution) == "hot")
        keys.push_back("hot");
      else if (std::string(distribution) == "distinct")
        keys.push_back(fmt::format("key-{:04}", i));
      else if (i % 100 == 0)
        keys.push_back("sparse");
      entries += keys.size();
      f.add(keys);
    }
    auto d = f.index->describe();
    CHECK(d["cache_peak_bytes"].get<size_t>() <= 1024);
    CHECK(
      d["update_path_peak_bytes"].get<size_t>() <=
      8 * 512 * d["height"].get<size_t>());
    CHECK(d["live_page_bytes"].get<size_t>() < entries * 100 + 512);
    CHECK(
      f.lfs->peak_batch_bytes <= d["working_set_limit_bytes"].get<size_t>() +
        512 * (2 * d["height"].get<size_t>() + 1));
    CHECK(f.lfs->peak_queue == 1);
    std::cout << "paged distribution=" << distribution << " entries=" << entries
              << " live_pages=" << d["live_pages"]
              << " live_bytes=" << d["live_page_bytes"]
              << " cache_peak=" << d["cache_peak_bytes"]
              << " path_peak=" << d["update_path_peak_bytes"]
              << " batch_peak=" << f.lfs->peak_batch_bytes
              << " queue_peak=" << f.lfs->peak_queue << '\n';
  }
}

TEST_CASE(
  "Paged cached traversals finish without yielding or decoding" *
  doctest::test_suite("paged"))
{
  Fixture f(8192);
  for (size_t i = 0; i < 100; ++i)
    f.add({"hot", std::to_string(i)});
  REQUIRE(f.index->describe()["recent_from"].get<size_t>() > 1);
  auto first = f.query("hot", 0, 10);
  REQUIRE(first.size() == 10);
  const auto before = f.index->describe();
  auto second = f.index->get_write_txs_in_range("hot", 1, 10);
  REQUIRE(second);
  CHECK(second->size() == 10);
  CHECK(f.lfs->work.empty());
  CHECK(f.index->describe()["page_decodes"] == before["page_decodes"]);
  CHECK(
    f.index->describe()["cache_hits"].get<size_t>() >
    before["cache_hits"].get<size_t>());
  CHECK(f.index->describe()["cache_peak_bytes"].get<size_t>() <= 8192);
}

TEST_CASE(
  "Paged bulk updates collect keys once with bounded checkpoint work" *
  doctest::test_suite("paged"))
{
  Fixture f(65536, 4096);
  std::vector<std::string> keys;
  for (size_t i = 0; i < 2048; ++i)
    keys.push_back(fmt::format("key-{:08}", i));
  f.begin(keys);
  CHECK_FALSE(f.index->get_write_txs_in_range(keys.front(), 0, 1));
  f.finish();
  f.flush();
  const auto state = f.index->describe();
  CHECK(state["key_visits"] == keys.size());
  CHECK(state["recent_from"] == 2);
  CHECK(
    state["key_buffer_peak_bytes"].get<size_t>() >=
    keys.size() * sizeof(ccf::ByteVector));
  CHECK(
    state["key_buffer_peak_bytes"].get<size_t>() <= 2 * keys.size() *
      (sizeof(ccf::ByteVector) +
       MapA::KeySerialiser::to_serialised(keys.back()).size()));
  CHECK(state["pending_key_buffer_bytes"] == 0);
  CHECK(
    state["working_set_peak_bytes"].get<size_t>() <=
    state["working_set_limit_bytes"].get<size_t>() +
      8 * 4096 * (2 * state["height"].get<size_t>() + 1));
  CHECK(f.lfs->stores < keys.size() / 2);
  CHECK(f.lfs->peak_queue == 1);
  CHECK(check_seqnos({1}, f.query(keys.front(), 0, 1)));
  CHECK(check_seqnos({1}, f.query(keys.back(), 0, 1)));
  CHECK(state["obsolete_pages"] == 0);
  CHECK(state["live_pages"] == f.lfs->disk.size());
}

TEST_CASE(
  "Paged key buffers do not retain historical stores or values" *
  doctest::test_suite("paged"))
{
  Fixture f(0, 512);
  f.add({"existing"});
  auto store = std::make_shared<ccf::kv::Store>();
  store->initialise_term(1);
  store->set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  {
    auto tx = store->create_tx();
    for (size_t i = 0; i < 500; ++i)
      tx.rw(map_a)->put(fmt::format("key-{:08}", i), std::string(4096, 'v'));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  std::weak_ptr<ccf::kv::ReadOnlyStore> weak = store;
  f.index->handle_committed_transaction({1, ++f.seqno}, store);
  REQUIRE_FALSE(f.index->next_requested());
  CHECK(f.index->describe()["pending_key_buffer_bytes"].get<size_t>() > 0);
  store.reset();
  CHECK(weak.expired());
  f.finish();
  f.flush();
  CHECK(f.index->describe()["pending_key_buffer_bytes"] == 0);
  CHECK(check_seqnos({2}, f.query("key-00000000", 0, 2)));
  CHECK(check_seqnos({2}, f.query("key-00000499", 0, 2)));
}

TEST_CASE(
  "Paged invalid keys reject the transaction before tree updates" *
  doctest::test_suite("paged"))
{
  Fixture f;
  f.begin({"a", "b", std::string(512, 'x')});
  const auto state = f.index->describe();
  CHECK(state["failed"] == true);
  CHECK(state["pending_key_buffer_bytes"] == 0);
  CHECK(state["pending_transaction"] == false);
  CHECK(state["live_pages"] == 0);
  CHECK(f.index->get_indexed_watermark().seqno == 0);
  CHECK(f.lfs->work.empty());
}

TEST_CASE(
  "Paged working root coalesces transactions without disk round trips" *
  doctest::test_suite("paged"))
{
  Fixture f(65536, 4096);
  for (size_t i = 0; i < 100; ++i)
  {
    f.begin({"hot"});
    f.finish();
  }
  CHECK(f.lfs->stores == 0);
  CHECK(f.lfs->work.empty());
  const auto recent = f.index->get_write_txs_in_range("hot", 90, 100);
  REQUIRE(recent);
  CHECK(recent->size() == 11);
  f.flush();
  CHECK(f.lfs->stores == 1);
  CHECK(f.index->describe()["key_visits"] == 100);
}

TEST_CASE(
  "Paged recent coverage preserves empty and boundary results" *
  doctest::test_suite("paged"))
{
  Fixture f(4096, 4096);
  for (size_t i = 1; i <= 500; ++i)
  {
    f.begin({fmt::format("key-{:08}", i)});
    f.finish();
  }
  f.flush();
  const ccf::SeqNo floor = f.index->describe()["recent_from"];
  REQUIRE(floor > 1);
  REQUIRE(floor <= f.seqno);
  auto latest = f.index->get_write_txs_in_range("key-00000500", floor, 500);
  CHECK(check_seqnos({500}, latest));
  auto empty = f.index->get_write_txs_in_range("missing", floor, 500);
  CHECK(check_seqnos({}, empty));
  CHECK(f.lfs->work.empty());
  const auto older = fmt::format("key-{:08}", floor - 1);
  CHECK(check_seqnos({floor - 1}, f.query(older, floor - 1, 500)));
  CHECK(check_seqnos({}, f.query(older, floor, 500)));
  CHECK(check_seqnos({1}, f.query("key-00000001", 0, 500)));
  CHECK(check_seqnos({}, f.query("", 0, 500)));
  f.begin({"key-00000001"});
  f.finish();
  CHECK(check_seqnos({1}, f.query("key-00000001", 0, 500)));
  CHECK(check_seqnos({1, 501}, f.query("key-00000001", 0, 501)));
  CHECK(f.index->describe()["cache_peak_bytes"].get<size_t>() <= 4096);
}

TEST_CASE(
  "Paged hot cache does not mask failed checkpoints" *
  doctest::test_suite("paged"))
{
  Fixture f(65536, 4096);
  f.begin({"hot"});
  f.finish();
  REQUIRE(f.index->get_write_txs_in_range("hot", 0, 1));
  f.lfs->fail_batch = true;
  f.index->flush();
  f.lfs->step();
  CHECK_FALSE(f.index->get_write_txs_in_range("hot", 0, 1));
  CHECK(f.index->describe()["failed"] == true);
}

TEST_CASE(
  "Paged failed mid-transaction checkpoints do not advance progress" *
  doctest::test_suite("paged"))
{
  Fixture f(4096);
  f.lfs->fail_batch = true;
  std::vector<std::string> keys;
  for (size_t i = 0; i < 500; ++i)
    keys.push_back(std::to_string(i));
  f.begin(keys);
  for (size_t i = 0; i < 1000 && !f.index->describe()["failed"].get<bool>();
       ++i)
  {
    f.lfs->step();
    f.index->tick();
  }
  CHECK(f.index->describe()["failed"] == true);
  CHECK(f.index->get_indexed_watermark().seqno == 0);
  CHECK_FALSE(f.index->next_requested());
  CHECK_FALSE(f.index->get_write_txs_in_range(keys.front(), 0, 1));
  CHECK(f.lfs->work.empty());
}

TEST_CASE(
  "Paged completed cursors do not pin obsolete roots or block writes" *
  doctest::test_suite("paged"))
{
  Fixture f;
  f.add({"a"});
  REQUIRE_FALSE(f.index->get_write_txs_in_range("a", 0, 1));
  f.lfs->step();
  f.index->tick();
  REQUIRE(f.index->describe()["query_active"] == true);
  f.begin({"b"});
  f.finish();
  f.flush();
  CHECK(f.index->get_indexed_watermark().seqno == 2);
  CHECK(check_seqnos({1}, f.query("a", 0, 1)));
  CHECK(check_seqnos({2}, f.query("b", 0, 2)));
}

TEST_CASE(
  "Paged LazyStrategy and real Indexer backpressure" *
  doctest::test_suite("paged"))
{
  Fixture f;
  using Lazy = LazyStrategy<Index>;
  auto lazy = std::make_shared<Lazy>(map_a, f.context, 512, 0);
  auto fetcher = std::make_shared<TestTransactionFetcher>();
  Indexer indexer(fetcher);
  REQUIRE(indexer.install_strategy(lazy));
  CHECK_FALSE(lazy->next_requested());
  lazy->extend_index_to({1, 2});
  std::map<ccf::SeqNo, ccf::kv::ReadOnlyStorePtr> historical;
  for (ccf::SeqNo i = 1; i <= 2; ++i)
  {
    auto store = std::make_shared<ccf::kv::Store>();
    store->initialise_term(1);
    auto consensus = std::make_shared<AllCommittableConsensus>();
    store->set_consensus(consensus);
    store->set_encryptor(fetcher->encryptor);
    for (ccf::SeqNo j = 1; j <= i; ++j)
    {
      auto tx = store->create_tx();
      tx.rw(map_a)->put("hot", std::to_string(j));
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
    const auto& entry = std::get<1>(consensus->replica.back());
    historical[i] =
      fetcher->deserialise_transaction(i, entry->data(), entry->size());
  }
  for (size_t i = 0; i < 1000 && lazy->get_indexed_watermark().seqno < 2; ++i)
  {
    indexer.update_strategies(step_time, {1, 2});
    for (const auto seqno : fetcher->requested)
      fetcher->fetched_stores[seqno] = historical.at(seqno);
    fetcher->requested.clear();
    f.lfs->step();
  }
  CHECK(lazy->get_indexed_watermark().seqno == 2);
  CHECK_FALSE(lazy->next_requested());
  std::optional<SeqNoCollection> result;
  for (size_t i = 0; i < 100 && !result; ++i)
  {
    result = lazy->get_write_txs_in_range("hot", 0, 2);
    f.lfs->step();
    lazy->tick();
  }
  CHECK(check_seqnos({1, 2}, result));
}
