// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_bucketed.h"
#include "indexing/enclave_lfs_access.h"
#include "indexing/test/common.h"
#include "tasks/job_board.h"

#include <doctest/doctest.h>

std::vector<uint8_t> read_file(const std::filesystem::path& p)
{
  std::ifstream f(p, std::ios::binary);
  f.seekg(0, f.end);
  const auto size = f.tellg();
  f.seekg(0, f.beg);
  std::vector<uint8_t> contents(size);
  f.read((char*)contents.data(), contents.size());
  f.close();
  return contents;
}

void write_file(
  const std::filesystem::path& p, const std::vector<uint8_t>& contents)
{
  std::ofstream f(p, std::ios::trunc | std::ios::binary);
  f.write((char const*)contents.data(), contents.size());
  f.close();
}

void write_file_corrupted_at(
  const std::filesystem::path& p,
  size_t i,
  const std::vector<uint8_t>& original)
{
  auto corrupted(original);
  REQUIRE(i < corrupted.size());
  corrupted[i]++;
  write_file(p, corrupted);
}

// Synchronously execute any LFS disk I/O actions (store/fetch) that have been
// queued on the given job board, returning the number of actions executed.
size_t flush_lfs(ccf::tasks::JobBoard& board)
{
  size_t count = 0;
  while (auto task = board.get_task())
  {
    task->do_task();
    ++count;
  }
  return count;
}

static std::vector<ActionDesc> create_actions(
  ExpectedSeqNos& seqnos_hello,
  ExpectedSeqNos& seqnos_saluton,
  ExpectedSeqNos& seqnos_1,
  ExpectedSeqNos& seqnos_2,
  ExpectedSeqNos& seqnos_set,
  ExpectedSeqNos& seqnos_value)
{
  std::vector<ActionDesc> actions;
  actions.push_back({seqnos_hello, [](size_t i, ccf::kv::Tx& tx) {
                       tx.wo(map_a)->put("hello", "value doesn't matter");
                       return true;
                     }});
  actions.push_back({seqnos_saluton, [](size_t i, ccf::kv::Tx& tx) {
                       if (i % 2 == 0)
                       {
                         tx.wo(map_a)->put("saluton", "value doesn't matter");
                         return true;
                       }
                       return false;
                     }});
  actions.push_back({seqnos_1, [](size_t i, ccf::kv::Tx& tx) {
                       if (i % 3 == 0)
                       {
                         tx.wo(map_b)->put(1, 42);
                         return true;
                       }
                       return false;
                     }});
  actions.push_back({seqnos_2, [](size_t i, ccf::kv::Tx& tx) {
                       if (i % 4 == 0)
                       {
                         tx.wo(map_b)->put(2, 42);
                         return true;
                       }
                       return false;
                     }});
  actions.push_back({seqnos_set, [](size_t i, ccf::kv::Tx& tx) {
                       if (i % 5 == 0)
                       {
                         tx.wo(set_a)->insert("set key");
                         return true;
                       }
                       return false;
                     }});
  actions.push_back({seqnos_value, [](size_t i, ccf::kv::Tx& tx) {
                       if (i % 6 == 0)
                       {
                         tx.wo(value_a)->put("value doesn't matter");
                         return true;
                       }
                       return false;
                     }});
  return actions;
}

TEST_CASE("Basic cache" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  const std::filesystem::path index_dir{".index"};

  ccf::indexing::EnclaveLFSAccess lfs_access(board);

  auto missing = lfs_access.fetch("Not stored");
  flush_lfs(board);
  REQUIRE(
    missing->fetch_result ==
    ccf::indexing::FetchResult::FetchResultType::NotFound);

  ccf::indexing::LFSKey key_a("Blob A");
  ccf::indexing::LFSContents blob_a{0, 1, 2, 3, 4, 5, 6, 7};

  ccf::indexing::LFSKey key_b("Blob B");
  ccf::indexing::LFSContents blob_b{'a', 'b', 'c'};

  lfs_access.store(key_a, ccf::indexing::LFSContents(blob_a));
  lfs_access.store(key_b, ccf::indexing::LFSContents(blob_b));

  REQUIRE(flush_lfs(board) > 0);

  {
    INFO("Load entries");

    auto result_a = lfs_access.fetch(key_a);
    REQUIRE(
      result_a->fetch_result ==
      ccf::indexing::FetchResult::FetchResultType::Fetching);

    auto result_b = lfs_access.fetch(key_b);
    REQUIRE(
      result_b->fetch_result ==
      ccf::indexing::FetchResult::FetchResultType::Fetching);

    flush_lfs(board);

    REQUIRE(
      result_a->fetch_result ==
      ccf::indexing::FetchResult::FetchResultType::Loaded);
    REQUIRE(result_a->contents == blob_a);

    REQUIRE(
      result_b->fetch_result ==
      ccf::indexing::FetchResult::FetchResultType::Loaded);
    REQUIRE(result_b->contents == blob_b);
  }

  {
    INFO("Cache provides wrong file");
    REQUIRE(std::filesystem::copy_file(
      index_dir / ccf::indexing::EnclaveLFSAccess::obfuscate_key(key_b),
      index_dir / ccf::indexing::EnclaveLFSAccess::obfuscate_key(key_a),
      std::filesystem::copy_options::overwrite_existing));

    auto result = lfs_access.fetch(key_a);

    flush_lfs(board);

    REQUIRE(
      result->fetch_result ==
      ccf::indexing::FetchResult::FetchResultType::Corrupt);
    REQUIRE(result->contents != blob_a);
  }

  const auto b_path =
    index_dir / ccf::indexing::EnclaveLFSAccess::obfuscate_key(key_b);
  const auto original_b_contents = read_file(b_path);

#ifndef PLAINTEXT_CACHE
  {
    INFO("Cache provides corrupt file");

    for (size_t i = 0; i < original_b_contents.size(); ++i)
    {
      write_file_corrupted_at(b_path, i, original_b_contents);

      auto result = lfs_access.fetch(key_b);

      flush_lfs(board);

      REQUIRE(
        result->fetch_result ==
        ccf::indexing::FetchResult::FetchResultType::Corrupt);
      REQUIRE(result->contents != blob_b);
    }
  }
#endif

  {
    INFO("Cache provides truncated file");

    // Every truncation must be reported as corrupt, including files too short
    // to contain a GCM header, rather than escaping as an exception
    for (size_t size = 0; size < original_b_contents.size(); ++size)
    {
      write_file(
        b_path,
        std::vector<uint8_t>(
          original_b_contents.begin(), original_b_contents.begin() + size));

      auto result = lfs_access.fetch(key_b);

      flush_lfs(board);

      REQUIRE(
        result->fetch_result ==
        ccf::indexing::FetchResult::FetchResultType::Corrupt);
      REQUIRE(result->contents != blob_b);
    }
  }

  {
    INFO("Cache provides oversized file");

    // Sparsely extend the file far beyond any blob this instance has written.
    // The read must be rejected by size, before any allocation is attempted.
    std::error_code ec;
    std::filesystem::resize_file(
      b_path, static_cast<std::uintmax_t>(1) << 40, ec);
    REQUIRE_MESSAGE(!ec, ec.message());

    auto result = lfs_access.fetch(key_b);

    flush_lfs(board);

    REQUIRE(
      result->fetch_result ==
      ccf::indexing::FetchResult::FetchResultType::Corrupt);
    REQUIRE(result->contents != blob_b);
  }

  {
    INFO("Restored file loads again");
    write_file(b_path, original_b_contents);

    auto result = lfs_access.fetch(key_b);

    flush_lfs(board);

    REQUIRE(
      result->fetch_result ==
      ccf::indexing::FetchResult::FetchResultType::Loaded);
    REQUIRE(result->contents == blob_b);
  }
}

TEST_CASE("Integrated cache" * doctest::test_suite("lfs"))
{
  ccf::kv::Store kv_store;

  auto consensus = std::make_shared<AllCommittableConsensus>();
  kv_store.set_consensus(consensus);

  auto fetcher = std::make_shared<TestTransactionFetcher>();
  ccf::indexing::Indexer indexer(fetcher);

  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  ccf::tasks::JobBoard board;
  const std::filesystem::path index_dir{".index"};

  auto lfs_access = std::make_shared<ccf::indexing::EnclaveLFSAccess>(board);

  ccf::AbstractNodeContext node_context;
  node_context.install_subsystem(lfs_access);

  using StratA =
    ccf::indexing::strategies::SeqnosByKey_Bucketed<decltype(map_a)>;
  auto index_a = std::make_shared<StratA>(map_a, node_context, 100, 4);
  REQUIRE(indexer.install_strategy(index_a));

  using StratSet =
    ccf::indexing::strategies::SeqnosByKey_Bucketed<decltype(set_a)>;
  auto index_set = std::make_shared<StratSet>(set_a, node_context, 100, 4);
  REQUIRE(indexer.install_strategy(index_set));

  using StratValue =
    ccf::indexing::strategies::SeqnosForValue_Bucketed<decltype(value_a)>;
  auto index_value =
    std::make_shared<StratValue>(value_a, node_context, 100, 4);
  REQUIRE(indexer.install_strategy(index_value));

  ExpectedSeqNos seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2, seqnos_set,
    seqnos_value;
  auto actions = create_actions(
    seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2, seqnos_set, seqnos_value);
  create_transactions(kv_store, actions);

  auto tick_until_caught_up = [&]() {
    while (indexer.update_strategies(step_time, kv_store.current_txid()) ||
           !fetcher->requested.empty())
    {
      // Do the fetch, simulating an asynchronous fetch by the historical query
      // system
      for (auto seqno : fetcher->requested)
      {
        REQUIRE(consensus->replica.size() >= seqno);
        const auto& entry = std::get<1>(consensus->replica[seqno - 1]);
        fetcher->fetched_stores[seqno] =
          fetcher->deserialise_transaction(seqno, entry->data(), entry->size());
      }
      fetcher->requested.clear();

      flush_lfs(board);
    }
  };

  tick_until_caught_up();
  REQUIRE(flush_lfs(board) == 0);

  auto current_seqno = kv_store.current_version();
  const auto max_requestable = index_a->max_requestable_range();
  REQUIRE(current_seqno > max_requestable);
  const auto request_range = max_requestable / 3;

  {
    INFO("Requestable range is limited");

    REQUIRE_THROWS(index_a->get_write_txs_in_range("hello", 0, current_seqno));
    REQUIRE_THROWS(
      index_a->get_write_txs_in_range("hello", 0, max_requestable + 1));
    REQUIRE_THROWS(index_a->get_write_txs_in_range(
      "hello", current_seqno - (max_requestable + 1), current_seqno));

    REQUIRE(flush_lfs(board) == 0);
  }

  auto fetch_all = [&](
                     auto& strat,
                     const auto& key,
                     const auto& expected,
                     bool should_fail = false) {
    auto range_start = 0;
    auto range_end = request_range;

    while (true)
    {
      LOG_INFO_FMT("Fetching {} from {} to {}", key, range_start, range_end);

      auto results = strat->get_write_txs_in_range(key, range_start, range_end);

      size_t retries = 0;
      while (!results.has_value())
      {
        REQUIRE(++retries <= current_seqno + 1);
        const auto flushed = flush_lfs(board);
        if (should_fail && flushed == 0)
        {
          return;
        }
        // This required an async load from disk
        REQUIRE(flushed > 0);

        results = strat->get_write_txs_in_range(key, range_start, range_end);
      }

      REQUIRE(check_seqnos(expected, results, false));

      if (range_end == current_seqno)
      {
        REQUIRE(!should_fail);
        break;
      }
      else
      {
        range_start = range_end + 1;
        range_end = std::min(range_start + request_range, current_seqno);
      }
    }
  };

  auto fetch_all_value = [&](
                           auto& strat,
                           const auto& expected,
                           bool should_fail = false) {
    auto range_start = 0;
    auto range_end = request_range;

    while (true)
    {
      LOG_TRACE_FMT(
        "Fetching {} from {} to {}", strat->get_name(), range_start, range_end);

      auto results = strat->get_write_txs_in_range(range_start, range_end);

      size_t retries = 0;
      while (!results.has_value())
      {
        REQUIRE(++retries <= current_seqno + 1);
        const auto flushed = flush_lfs(board);
        if (should_fail && flushed == 0)
        {
          return;
        }
        // This required an async load from disk
        REQUIRE(flushed > 0);

        results = strat->get_write_txs_in_range(range_start, range_end);
      }

      REQUIRE(check_seqnos(expected, results, false));

      if (range_end == current_seqno)
      {
        REQUIRE(!should_fail);
        break;
      }
      else
      {
        range_start = range_end + 1;
        range_end = std::min(range_start + request_range, current_seqno);
      }
    }
  };

  {
    INFO("Old entries must be fetched asynchronously");

    fetch_all(index_a, "hello", seqnos_hello);
    fetch_all(index_a, "saluton", seqnos_saluton);
  }

  INFO(
    "Indexes can be installed later, and will be populated after enough "
    "ticks");

  using StratB =
    ccf::indexing::strategies::SeqnosByKey_Bucketed<decltype(map_b)>;
  auto index_b = std::make_shared<StratB>(map_b, node_context, 100, 4);
  REQUIRE(indexer.install_strategy(index_b));

  ccf::TxID current = kv_store.current_txid();
  REQUIRE(index_a->get_indexed_watermark() == current);
  REQUIRE(index_b->get_indexed_watermark() == ccf::TxID());

  tick_until_caught_up();

  REQUIRE(index_a->get_indexed_watermark() == current);
  REQUIRE(index_b->get_indexed_watermark() == current);

  fetch_all(index_b, 1, seqnos_1);
  fetch_all(index_b, 2, seqnos_2);

  {
    INFO("Both indexes continue to be updated with new entries");
    REQUIRE(create_transactions(kv_store, actions));

    current = kv_store.current_txid();
    current_seqno = current.seqno;

    tick_until_caught_up();

    REQUIRE(index_a->get_indexed_watermark() == current);
    REQUIRE(index_b->get_indexed_watermark() == current);

    fetch_all(index_a, "hello", seqnos_hello);
    fetch_all(index_a, "saluton", seqnos_saluton);

    fetch_all(index_b, 1, seqnos_1);
    fetch_all(index_b, 2, seqnos_2);

    fetch_all(index_set, "set key", seqnos_set);
    fetch_all_value(index_value, seqnos_value);
  }

  {
    INFO("Invalid disk cache leads to index being rebuilt");

    auto identify_error_and_reindex = [&]() {
      fetch_all(index_a, "hello", seqnos_hello, true);

      // Queries request a rebuild without resetting the watermark themselves.
      REQUIRE(index_a->get_indexed_watermark() == current);
      REQUIRE(index_b->get_indexed_watermark() == current);
      REQUIRE_FALSE(
        index_a->get_write_txs_in_range("hello", current_seqno, current_seqno)
          .has_value());

      fetch_all(index_b, 1, seqnos_1, true);
      fetch_all(index_set, "set key", seqnos_set, true);
      fetch_all_value(index_value, seqnos_value, true);

      REQUIRE(index_b->get_indexed_watermark() == current);
      REQUIRE_FALSE(
        index_b->get_write_txs_in_range(1, current_seqno, current_seqno)
          .has_value());

      // This call does the actual re-indexing
      tick_until_caught_up();
      REQUIRE(index_a->get_indexed_watermark() == current);
      REQUIRE(index_b->get_indexed_watermark() == current);

      fetch_all(index_a, "hello", seqnos_hello);
      fetch_all(index_a, "saluton", seqnos_saluton);

      fetch_all(index_b, 1, seqnos_1);
      fetch_all(index_b, 2, seqnos_2);

      fetch_all(index_set, "set key", seqnos_set);
      fetch_all_value(index_value, seqnos_value);
    };

    // Note: We delete/corrupt every file, since we don't know which files apply
    // to which indexes/buckets

    {
      INFO("Deleted files");
      for (auto const& f : std::filesystem::directory_iterator(index_dir))
      {
        std::filesystem::remove(f);
      }

      identify_error_and_reindex();
    }

    {
      INFO("Corrupted files");
      for (auto const& f : std::filesystem::directory_iterator(index_dir))
      {
        auto original = read_file(f);

#ifndef PLAINTEXT_CACHE
        // With encrypted files, corruption of any single byte should be
        // recognised as corruption
        write_file_corrupted_at(f, rand() % original.size(), original);
#else
        // For plaintext files, make a simple corruption of resizing them, so
        // bytes remain after parsing
        original.resize(original.size() + 1);

        std::ofstream ofs(f, std::ios::trunc | std::ios::binary);
        ofs.write((char const*)original.data(), original.size());
        ofs.close();
#endif
      }

      identify_error_and_reindex();
    }
  }
}

void run_sparse_index_test(size_t bucket_size, size_t num_buckets)
{
  ccf::kv::Store kv_store;

  auto consensus = std::make_shared<AllCommittableConsensus>();
  kv_store.set_consensus(consensus);

  auto fetcher = std::make_shared<TestTransactionFetcher>();
  ccf::indexing::Indexer indexer(fetcher);

  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  ccf::tasks::JobBoard board;

  auto lfs_access = std::make_shared<ccf::indexing::EnclaveLFSAccess>(board);

  ccf::AbstractNodeContext node_context;
  node_context.install_subsystem(lfs_access);

  using Strat = ccf::indexing::LazyStrategy<
    ccf::indexing::strategies::SeqnosByKey_Bucketed<decltype(map_b)>>;
  const auto many_buckets = bucket_size * (num_buckets + 1);
  auto index =
    std::make_shared<Strat>(map_b, node_context, bucket_size, num_buckets);
  REQUIRE(indexer.install_strategy(index));

  constexpr auto key_always = 0;
  constexpr auto key_never = 1;
  constexpr auto key_early = 2;
  constexpr auto key_mid = 3;
  constexpr auto key_late = 4;

  std::map<size_t, std::vector<ccf::SeqNo>> all_writes;

  auto write_to_map_b = [&](size_t count, const std::vector<size_t>& keys) {
    for (size_t i = 0; i < count; ++i)
    {
      auto tx = kv_store.create_tx();
      auto handle_b = tx.wo(map_b);
      for (const auto& k : keys)
      {
        handle_b->put(k, k);
      }
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      const auto seqno = tx.get_txid()->seqno;
      for (const auto& k : keys)
      {
        all_writes[k].push_back(seqno);
      }
    }
  };

  auto write_to_map_a = [&](size_t count) {
    for (size_t i = 0; i < count; ++i)
    {
      auto tx = kv_store.create_tx();
      auto handle_a = tx.wo(map_a);
      handle_a->put("ignore", "ignore");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  };

  // First bucket contains writes to key_always and key_early
  write_to_map_b(bucket_size, {key_always, key_early});

  // Several buckets contains writes to only key_always
  write_to_map_b(many_buckets, {key_always});

  // Several buckets contain writes to other maps entirely
  write_to_map_a(many_buckets);

  // Middle bucket contains writes to key_always and key_mid
  write_to_map_b(bucket_size, {key_always, key_mid});

  // Several buckets contain writes to other maps entirely
  write_to_map_a(many_buckets);

  // Several buckets contains writes to only key_always
  write_to_map_b(many_buckets, {key_always});

  // Final bucket contains writes to key_always and key_late
  write_to_map_b(bucket_size, {key_always, key_late});

  auto tick_until_caught_up = [&]() {
    index->extend_index_to(kv_store.current_txid());
    while (indexer.update_strategies(step_time, kv_store.current_txid()) ||
           !fetcher->requested.empty())
    {
      // Do the fetch, simulating an asynchronous fetch by the historical query
      // system
      for (auto seqno : fetcher->requested)
      {
        REQUIRE(consensus->replica.size() >= seqno);
        const auto& entry = std::get<1>(consensus->replica[seqno - 1]);
        fetcher->fetched_stores[seqno] =
          fetcher->deserialise_transaction(seqno, entry->data(), entry->size());
      }
      fetcher->requested.clear();

      flush_lfs(board);
    }
  };

  tick_until_caught_up();
  REQUIRE(flush_lfs(board) == 0);

  auto fetch_write_seqnos = [&](size_t key) {
    const auto max_range = index->max_requestable_range();
    const auto end_seqno = kv_store.current_txid().seqno;

    auto range_start = 0;

    auto next_end = [&]() {
      const auto r = rand();
      return std::min(end_seqno, range_start + 1 + (r % (max_range - 2)));
    };

    auto range_end = next_end();

    std::vector<ccf::SeqNo> writes;
    while (true)
    {
      LOG_INFO_FMT("Fetching {} from {} to {}", key, range_start, range_end);

      auto results = index->get_write_txs_in_range(key, range_start, range_end);

      size_t retries = 0;
      while (!results.has_value())
      {
        REQUIRE(++retries <= end_seqno + 1);
        // This required an async load from disk
        REQUIRE(flush_lfs(board) > 0);

        results = index->get_write_txs_in_range(key, range_start, range_end);
      }

      LOG_INFO_FMT("Found {} more entries", results->size());

      for (auto seqno : *results)
      {
        writes.push_back(seqno);
      }

      if (range_end == end_seqno)
      {
        return writes;
      }
      else
      {
        range_start = range_end + 1;
        range_end = next_end();
      }
    }
  };

  for (const auto& k : {key_always, key_never, key_early, key_mid, key_late})
  {
    const auto& expected = all_writes[k];
    INFO("Checking key: " << k);
    const auto actual = fetch_write_seqnos(k);
    REQUIRE(expected.size() == actual.size());
    REQUIRE(expected == actual);
  }
}

TEST_CASE("Sparse index" * doctest::test_suite("lfs"))
{
  run_sparse_index_test(5, 3);
  run_sparse_index_test(8, 6);
  run_sparse_index_test(500, 10);
  run_sparse_index_test(5, 300);

  const auto seed = time(NULL);
  INFO("Using seed: ", seed);
  srand(seed);

  for (auto i = 0; i < 20; ++i)
  {
    const auto bucket_size = (rand() % 100) + 5;
    const auto num_buckets = (rand() % 20) + 3;
    INFO(
      "Testing sparse index with " << num_buckets << " buckets of size "
                                   << bucket_size);
    run_sparse_index_test(bucket_size, num_buckets);
  }
}

class CountingLFS : public ccf::indexing::EnclaveLFSAccess
{
public:
  using EnclaveLFSAccess::EnclaveLFSAccess;
  std::vector<ccf::indexing::LFSKey> stores;
  std::vector<ccf::indexing::LFSKey> fetches;
  std::vector<ccf::indexing::LFSKey> data_stores;
  std::vector<ccf::indexing::LFSKey> page_stores;
  std::vector<ccf::indexing::LFSKey> data_fetches;
  std::vector<ccf::indexing::LFSKey> page_fetches;

  void store(
    const ccf::indexing::LFSKey& key,
    ccf::indexing::LFSContents&& contents) override
  {
    stores.push_back(key);
    (key.find(": directory ") == std::string::npos ? data_stores : page_stores)
      .push_back(key);
    EnclaveLFSAccess::store(key, std::move(contents));
  }

  ccf::indexing::FetchResultPtr fetch(const ccf::indexing::LFSKey& key) override
  {
    fetches.push_back(key);
    (key.find(": directory ") == std::string::npos ? data_fetches :
                                                     page_fetches)
      .push_back(key);
    return EnclaveLFSAccess::fetch(key);
  }
};

class SparseBucketTestIndex
  : public ccf::indexing::strategies::SeqnosByKey_Bucketed<MapA>
{
public:
  using SeqnosByKey_Bucketed::describe;
  using SeqnosByKey_Bucketed::SeqnosByKey_Bucketed;

  // Exercise sparse seqnos without constructing millions of unrelated KV txs.
  void write(ccf::SeqNo seqno, const std::string& key)
  {
    visit_entry({1, seqno}, MapA::KeySerialiser::to_serialised(key), {});
    std::lock_guard<ccf::ds::Mutex> guard(current_txid_lock);
    current_txid = {1, seqno};
  }
};

TEST_CASE("Sparse bucket stores and fetches" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  SparseBucketTestIndex index(map_a, context, 1000, 4);

  index.write(1, "early");
  index.write(1'000'000, "late");
  CHECK(lfs->stores.empty());
  index.write(2'000'000, "early");
  REQUIRE(lfs->stores.size() == 1);
  for (size_t i = 0; i < 100; ++i)
  {
    index.write(5'000'000 + i, fmt::format("key{}", i));
  }
  CHECK(lfs->stores.size() == 1);
  flush_lfs(board);
  CHECK(
    std::distance(
      std::filesystem::directory_iterator(".index"),
      std::filesystem::directory_iterator{}) == 1);

  auto before_first = index.get_write_txs_in_range("late", 998'000, 999'999);
  REQUIRE(before_first.has_value());
  CHECK(before_first->empty());
  CHECK(lfs->fetches.empty());

  auto gap = index.get_write_txs_in_range("early", 998'000, 999'999);
  REQUIRE(gap.has_value());
  CHECK(gap->empty());
  CHECK(lfs->fetches.empty());

  auto early = index.get_write_txs_in_range("early", 0, 1000);
  CHECK_FALSE(early.has_value());
  REQUIRE(lfs->fetches.size() == 1);
  CHECK_FALSE(index.get_write_txs_in_range("early", 0, 1000).has_value());
  CHECK(lfs->fetches.size() == 1);
  flush_lfs(board);

  CHECK(check_seqnos({1}, index.get_write_txs_in_range("early", 0, 1000)));
  CHECK(check_seqnos(
    {1'000'000}, index.get_write_txs_in_range("late", 999'999, 1'000'000)));
  CHECK(check_seqnos(
    {}, index.get_write_txs_in_range("absent", 1'000'000, 1'000'001)));
  CHECK_FALSE(
    index.get_write_txs_in_range("absent", 5'000'100, 5'000'100).has_value());
  CHECK_THROWS(index.get_write_txs_in_range("early", 2, 1));
  CHECK_THROWS(index.get_write_txs_in_range("early", 0, 3001));
  CHECK_THROWS(SparseBucketTestIndex(map_a, context, 0, 4));
  CHECK_THROWS(SparseBucketTestIndex(map_a, context, 10, 0));
}

TEST_CASE(
  "Sparse bucket batched reads and boundaries" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  SparseBucketTestIndex index(map_a, context, 10, 2);

  for (auto seqno : {1, 10, 19, 40, 80, 120, 160, 200})
  {
    index.write(seqno, "chain");
  }
  REQUIRE(lfs->stores.size() == 6);

  // Queue both reads before flushing stores, exercising ordered LFS I/O.
  auto result = index.get_write_txs_in_range("chain", 0, 10);
  CHECK_FALSE(result.has_value());
  CHECK_FALSE(index.get_write_txs_in_range("chain", 0, 10).has_value());
  REQUIRE(lfs->fetches.size() == 2);
  // Advancing the head must not invalidate an in-flight older-range query.
  index.write(240, "chain");
  for (size_t retry = 0; !result.has_value() && retry < 7; ++retry)
  {
    REQUIRE(flush_lfs(board) > 0);
    result = index.get_write_txs_in_range("chain", 0, 10);
  }
  REQUIRE(check_seqnos({1, 10}, result));
  CHECK(lfs->fetches.size() == 2);

  for (auto from : {0, 1, 9, 10, 11, 19, 20, 39, 40, 41, 199, 200, 201, 240})
  {
    INFO("Range starts at " << from);
    const auto to = std::min(from + 10, 240);
    ExpectedSeqNos expected;
    for (auto seqno : {1, 10, 19, 40, 80, 120, 160, 200, 240})
    {
      if (seqno >= from && seqno <= to)
      {
        expected.insert(seqno);
      }
    }
    auto range = index.get_write_txs_in_range("chain", from, to);
    for (size_t retry = 0; !range.has_value() && retry < 8; ++retry)
    {
      REQUIRE(flush_lfs(board) > 0);
      range = index.get_write_txs_in_range("chain", from, to);
    }
    REQUIRE(check_seqnos(expected, range));
  }
}

TEST_CASE("Sparse bucket required files" * doctest::test_suite("lfs"))
{
  for (const auto& fault : {"missing", "corrupt", "substituted"})
  {
    for (size_t target : {0, 1, 2})
    {
      for (bool gap : {false, true})
      {
        INFO("Fault " << fault << ", bucket " << target << ", gap " << gap);
        ccf::tasks::JobBoard board;
        auto lfs = std::make_shared<CountingLFS>(board);
        ccf::AbstractNodeContext context;
        context.install_subsystem(lfs);
        ccf::indexing::LazyStrategy<SparseBucketTestIndex> index(
          map_a, context, 10, 2);
        index.extend_index_to({1, 3000});
        for (auto seqno : {1, 1000, 2000, 3000})
        {
          index.write(seqno, "chain");
        }
        REQUIRE(lfs->stores.size() == 3);
        flush_lfs(board);
        const auto path = std::filesystem::path(".index") /
          CountingLFS::obfuscate_key(lfs->stores[target]);
        if (std::string(fault) == "missing")
        {
          REQUIRE(std::filesystem::remove(path));
        }
        else if (std::string(fault) == "corrupt")
        {
          auto contents = read_file(path);
          write_file_corrupted_at(path, contents.size() - 1, contents);
        }
        else
        {
          const auto other = std::filesystem::path(".index") /
            CountingLFS::obfuscate_key(lfs->stores[(target + 1) % 3]);
          REQUIRE(std::filesystem::copy_file(
            other, path, std::filesystem::copy_options::overwrite_existing));
        }

        const ccf::SeqNo from =
          target * 1000 + (gap ? 5 : (target == 0 ? 1 : 0));
        auto result = index.get_write_txs_in_range("chain", from, from);
        index.tick();
        for (size_t retry = 0;
             index.get_indexed_watermark().seqno != 0 && retry < 4;
             ++retry)
        {
          REQUIRE_FALSE(result.has_value());
          REQUIRE(flush_lfs(board) > 0);
          result = index.get_write_txs_in_range("chain", from, from);
          index.tick();
        }
        CHECK_FALSE(result.has_value());
        REQUIRE(index.get_indexed_watermark() == ccf::TxID());
        CHECK(index.next_requested() == 1);
        // Clearing trusted heads on failure must not look like an absent key.
        CHECK_FALSE(
          index.get_write_txs_in_range("chain", from, from).has_value());

        for (auto seqno : {1, 1000, 2000, 3000})
        {
          index.write(seqno, "chain");
        }
        result = index.get_write_txs_in_range("chain", from, from);
        for (size_t retry = 0; !result.has_value() && retry < 5; ++retry)
        {
          REQUIRE(flush_lfs(board) > 0);
          result = index.get_write_txs_in_range("chain", from, from);
        }
        REQUIRE(
          check_seqnos(gap ? ExpectedSeqNos{} : ExpectedSeqNos{from}, result));
        CHECK_FALSE(index.next_requested().has_value());
      }
    }
  }
}

TEST_CASE("Sparse bucket direct old-range lookup" * doctest::test_suite("lfs"))
{
  for (size_t buckets : {100, 1000})
  {
    INFO("Non-empty history has " << buckets << " buckets");
    ccf::tasks::JobBoard board;
    auto lfs = std::make_shared<CountingLFS>(board);
    ccf::AbstractNodeContext context;
    context.install_subsystem(lfs);
    SparseBucketTestIndex index(map_a, context, 10, 3);
    for (size_t bucket = 0; bucket < buckets; ++bucket)
    {
      index.write(bucket * 10 + 1, "dense");
    }

    // Both requested buckets are far older than the trusted head. No newer
    // bucket should be read, irrespective of how much history follows them.
    auto result = index.get_write_txs_in_range("dense", 0, 19);
    REQUIRE_FALSE(result.has_value());
    CHECK_FALSE(index.get_write_txs_in_range("dense", 0, 19).has_value());
    REQUIRE(lfs->fetches.size() == 2);
    CHECK(lfs->fetches[0] == lfs->data_stores[0]);
    REQUIRE(flush_lfs(board) > 0);
    result = index.get_write_txs_in_range("dense", 0, 19);
    REQUIRE(check_seqnos({1, 11}, result));
    REQUIRE(lfs->fetches.size() == 2);
    CHECK(lfs->fetches[1] == lfs->data_stores[1]);
    CHECK(lfs->page_fetches.empty());
    CHECK(lfs->page_stores.size() == (buckets - 1) / 256);
    CHECK(check_seqnos({1}, index.get_write_txs_in_range("dense", 1, 1)));
    CHECK(lfs->fetches.size() == 2);

    // Losing an unrelated newer bucket must not obstruct this direct path.
    REQUIRE(std::filesystem::remove(
      std::filesystem::path(".index") /
      CountingLFS::obfuscate_key(lfs->data_stores[buckets / 2])));
    CHECK(check_seqnos({11}, index.get_write_txs_in_range("dense", 10, 19)));
    CHECK(lfs->fetches.size() == 2);
  }
}

TEST_CASE("Sparse bucket in-memory directory gaps" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  SparseBucketTestIndex index(map_a, context, 10, 3);
  for (auto seqno : {1, 11, 100, 200, 300, 400, 500})
  {
    index.write(seqno, "chain");
  }
  auto result = index.get_write_txs_in_range("chain", 10, 25);
  REQUIRE_FALSE(result.has_value());
  for (size_t retry = 0; !result.has_value() && retry < 7; ++retry)
  {
    REQUIRE(flush_lfs(board) > 0);
    result = index.get_write_txs_in_range("chain", 10, 25);
  }
  REQUIRE(check_seqnos({11}, result));
  CHECK(lfs->fetches.size() == 1);
  CHECK(check_seqnos({}, index.get_write_txs_in_range("chain", 20, 25)));
  CHECK(lfs->fetches.size() == 1);
  CHECK(index.get_indexed_watermark().seqno == 500);
}

TEST_CASE(
  "Sparse bucket direct hit is not a partial result" *
  doctest::test_suite("lfs"))
{
  for (bool corrupt : {false, true})
  {
    ccf::tasks::JobBoard board;
    auto lfs = std::make_shared<CountingLFS>(board);
    ccf::AbstractNodeContext context;
    context.install_subsystem(lfs);
    SparseBucketTestIndex index(map_a, context, 10, 3);
    for (auto seqno : {1, 11, 100, 200})
    {
      index.write(seqno, "chain");
    }
    flush_lfs(board);
    const auto path = std::filesystem::path(".index") /
      CountingLFS::obfuscate_key(lfs->stores[1]);
    if (corrupt)
    {
      auto contents = read_file(path);
      write_file_corrupted_at(path, contents.size() - 1, contents);
    }
    else
    {
      REQUIRE(std::filesystem::remove(path));
    }
    auto result = index.get_write_txs_in_range("chain", 0, 19);
    CHECK_FALSE(result.has_value());
    flush_lfs(board);
    result = index.get_write_txs_in_range("chain", 0, 19);
    // The first direct hit contains seqno 1, but the other required file is
    // unavailable. That accumulated partial result must never escape.
    CHECK_FALSE(result.has_value());
    REQUIRE(lfs->fetches.size() == 2);
    CHECK(lfs->fetches[0] == lfs->stores[0]);
    CHECK(lfs->fetches[1] == lfs->stores[1]);
    flush_lfs(board);
    CHECK_FALSE(index.get_write_txs_in_range("chain", 0, 19).has_value());
    index.tick();
    CHECK(index.get_indexed_watermark() == ccf::TxID());
  }
}

TEST_CASE("Sparse bucket dense range is one batch" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  SparseBucketTestIndex index(map_a, context, 10, 101);
  for (size_t bucket = 0; bucket <= 1024; ++bucket)
  {
    index.write(bucket * 10 + 1, "dense");
  }
  auto result = index.get_write_txs_in_range("dense", 0, 999);
  REQUIRE_FALSE(result.has_value());
  CHECK(lfs->data_fetches.size() == 100);
  CHECK_FALSE(index.get_write_txs_in_range("dense", 0, 999).has_value());
  CHECK(lfs->data_fetches.size() == 100);
  REQUIRE(flush_lfs(board) > 0);
  result = index.get_write_txs_in_range("dense", 0, 999);
  ExpectedSeqNos expected;
  for (size_t bucket = 0; bucket < 100; ++bucket)
  {
    expected.insert(bucket * 10 + 1);
  }
  REQUIRE(check_seqnos(expected, result));
  CHECK(lfs->data_fetches.size() == 100);
  CHECK(lfs->page_fetches.empty());
  CHECK(lfs->data_stores.size() == 1024);
  CHECK(lfs->page_stores.size() == 4);
}

TEST_CASE(
  "Sparse bucket mixed cached fragmented results" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  constexpr ccf::SeqNo bucket_size = 10'000;
  SparseBucketTestIndex index(map_a, context, bucket_size, 20);
  for (ccf::SeqNo seqno = 1; seqno <= 19 * bucket_size + 1; seqno += 2)
  {
    index.write(seqno, "fragmented");
  }
  // Warm the newer nine buckets first, then mix their cached contents with
  // ten older disk reads. The result must be assembled in ascending order,
  // not by inserting older entries ahead of 45,000 already-cached seqnos.
  auto warm = index.get_write_txs_in_range(
    "fragmented", 10 * bucket_size, 19 * bucket_size - 1);
  REQUIRE_FALSE(warm.has_value());
  flush_lfs(board);
  warm = index.get_write_txs_in_range(
    "fragmented", 10 * bucket_size, 19 * bucket_size - 1);
  REQUIRE(warm.has_value());
  CHECK(warm->size() == 45'000);
  auto result =
    index.get_write_txs_in_range("fragmented", 0, 19 * bucket_size - 1);
  REQUIRE_FALSE(result.has_value());
  CHECK(lfs->data_fetches.size() == 19);
  flush_lfs(board);
  result = index.get_write_txs_in_range("fragmented", 0, 19 * bucket_size - 1);
  REQUIRE(result.has_value());
  std::vector<ccf::SeqNo> expected;
  for (ccf::SeqNo seqno = 1; seqno < 19 * bucket_size; seqno += 2)
  {
    expected.push_back(seqno);
  }
  CHECK(std::equal(
    result->begin(), result->end(), expected.begin(), expected.end()));
  CHECK(lfs->data_fetches.size() == 19);
}

TEST_CASE(
  "Sparse bucket repeated ranges reuse bucket cache" *
  doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  constexpr size_t cache_slots = 20;
  constexpr ccf::SeqNo bucket_size = 100;
  constexpr ccf::SeqNo width = (cache_slots - 1) * bucket_size;
  SparseBucketTestIndex index(map_a, context, bucket_size, cache_slots);
  for (ccf::SeqNo seqno = 1; seqno <= width + 2 * cache_slots + 1; seqno += 2)
  {
    index.write(seqno, "fragmented");
  }

  for (ccf::SeqNo from = 0; from < cache_slots; ++from)
  {
    auto result =
      index.get_write_txs_in_range("fragmented", from, from + width);
    if (!result.has_value())
    {
      CHECK(index.describe()["directory_searches_current_size"] == 0);
      REQUIRE(flush_lfs(board) > 0);
      result = index.get_write_txs_in_range("fragmented", from, from + width);
    }

    ExpectedSeqNos expected;
    for (auto seqno = from | 1; seqno <= from + width; seqno += 2)
    {
      expected.insert(seqno);
    }
    REQUIRE(check_seqnos(expected, result));
    CHECK(index.describe()["directory_searches_current_size"] == 0);
    CHECK(index.describe()["old_results_current_size"] <= cache_slots);

    // Identical and overlapping ranges reuse the same bounded bucket cache.
    const auto fetches = lfs->fetches.size();
    REQUIRE(check_seqnos(
      expected,
      index.get_write_txs_in_range("fragmented", from, from + width)));
    CHECK(lfs->fetches.size() == fetches);
    CHECK(index.describe()["directory_searches_current_size"] == 0);
  }
}

TEST_CASE("Sparse bucket paged directory costs" * doctest::test_suite("lfs"))
{
  const std::pair<size_t, ccf::SeqNo> cases[] = {
    {4, 20}, {40, 20}, {40, 1'000'000}};
  for (auto [pages, gap] : cases)
  {
    INFO("Directory pages: " << pages);
    ccf::tasks::JobBoard board;
    auto lfs = std::make_shared<CountingLFS>(board);
    ccf::AbstractNodeContext context;
    context.install_subsystem(lfs);
    SparseBucketTestIndex index(map_a, context, 10, 1);
    const auto completed_buckets = pages * 256;
    for (size_t bucket = 0; bucket <= completed_buckets; ++bucket)
    {
      index.write(bucket * gap + 1, "sparse");
    }
    CHECK(lfs->data_stores.size() == completed_buckets);
    CHECK(lfs->page_stores.size() == pages);
    size_t search_reads = 0;
    for (auto count = pages; count != 0; count /= 2)
    {
      ++search_reads;
    }
    auto result = index.get_write_txs_in_range("sparse", 10, 10);
    for (size_t retry = 0; !result.has_value() && retry < search_reads + 1;
         ++retry)
    {
      const auto fetches = lfs->fetches.size();
      CHECK_FALSE(index.get_write_txs_in_range("sparse", 10, 10).has_value());
      CHECK(lfs->fetches.size() == fetches);
      REQUIRE(flush_lfs(board) > 0);
      result = index.get_write_txs_in_range("sparse", 10, 10);
    }
    REQUIRE(check_seqnos({}, result));
    CHECK(lfs->data_fetches.size() == 1);
    CHECK(lfs->page_fetches.size() == search_reads);
    CHECK(index.describe()["directory_pages_current_size"] == 1);
    CHECK(index.describe()["directory_searches_current_size"] == 0);
    const auto fetches = lfs->fetches.size();
    REQUIRE(check_seqnos({}, index.get_write_txs_in_range("sparse", 10, 10)));
    CHECK(lfs->fetches.size() == fetches);
    // Both the data read count and the retry count are independent of the
    // ledger gaps. Only logarithmically many small metadata pages were read.
  }
}

TEST_CASE("Sparse bucket directory boundaries" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  SparseBucketTestIndex index(map_a, context, 10, 6);
  constexpr ccf::SeqNo base = 1'000'000;
  for (size_t bucket = 0; bucket <= 513; ++bucket)
  {
    index.write(base + bucket * 20 + 1, "late");
  }
  CHECK(lfs->page_stores.size() == 2);
  CHECK(lfs->data_stores.size() == 513);
  auto get = [&](ccf::SeqNo from, ccf::SeqNo to) {
    auto result = index.get_write_txs_in_range("late", from, to);
    for (size_t retry = 0; !result.has_value() && retry < 5; ++retry)
    {
      REQUIRE(flush_lfs(board) > 0);
      result = index.get_write_txs_in_range("late", from, to);
    }
    REQUIRE(result.has_value());
    return result;
  };
  // Cross two sealed pages, with an empty bucket between the two data buckets.
  REQUIRE(
    check_seqnos({base + 5101, base + 5121}, get(base + 5101, base + 5121)));
  CHECK(lfs->data_fetches.size() == 3);
  CHECK(lfs->page_fetches.size() == 2);
  // Cross the last sealed page, unfinished page, and current data bucket.
  REQUIRE(check_seqnos(
    {base + 10221, base + 10241, base + 10261},
    get(base + 10221, base + 10261)));
  REQUIRE(check_seqnos({}, get(0, 0)));
  REQUIRE(check_seqnos({}, get(base + 5130, base + 5139)));
  REQUIRE(check_seqnos({base + 5121}, get(base + 5121, base + 5121)));
  REQUIRE(check_seqnos({}, get(base + 10250, base + 10259)));
}

TEST_CASE(
  "Sparse bucket overlapping directory searches" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  SparseBucketTestIndex index(map_a, context, 10, 4);
  for (size_t bucket = 0; bucket <= 8 * 256; ++bucket)
  {
    index.write(bucket * 20 + 1, "key");
  }

  // Neither request owns a snapshot of buckets or partial results. The
  // shared caches must let both ranges finish, including their common gap.
  auto first = index.get_write_txs_in_range("key", 5091, 5121);
  auto second = index.get_write_txs_in_range("key", 5101, 5129);
  REQUIRE_FALSE(first.has_value());
  REQUIRE_FALSE(second.has_value());
  CHECK(index.describe()["old_results_current_size"] == 4);
  index.write(50'001, "key");
  for (size_t retry = 0;
       (!first.has_value() || !second.has_value()) && retry < 8;
       ++retry)
  {
    REQUIRE(flush_lfs(board) > 0);
    first = index.get_write_txs_in_range("key", 5091, 5121);
    second = index.get_write_txs_in_range("key", 5101, 5129);
  }
  REQUIRE(check_seqnos({5101, 5121}, first));
  REQUIRE(check_seqnos({5101, 5121}, second));
  CHECK(lfs->data_fetches.size() == 4);
  CHECK(index.describe()["directory_searches_current_size"] == 0);
  const auto fetches = lfs->fetches.size();
  REQUIRE(check_seqnos(
    {5101, 5121}, index.get_write_txs_in_range("key", 5091, 5121)));
  REQUIRE(check_seqnos(
    {5101, 5121}, index.get_write_txs_in_range("key", 5101, 5129)));
  CHECK(lfs->fetches.size() == fetches);
}

TEST_CASE(
  "Sparse bucket directory sealing during a query" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  SparseBucketTestIndex index(map_a, context, 10, 4);
  for (size_t bucket = 0; bucket < 256; ++bucket)
  {
    index.write(bucket * 20 + 1, "key");
  }
  CHECK(lfs->page_stores.empty());
  CHECK_FALSE(index.get_write_txs_in_range("key", 1, 21).has_value());
  REQUIRE(lfs->data_fetches.size() == 2);
  index.write(5121, "key");
  REQUIRE(lfs->page_stores.size() == 1);
  flush_lfs(board);
  REQUIRE(check_seqnos({1, 21}, index.get_write_txs_in_range("key", 1, 21)));
  CHECK(lfs->page_fetches.empty());
}

TEST_CASE("Sparse bucket required directory pages" * doctest::test_suite("lfs"))
{
  for (const auto& fault :
       {"missing", "corrupt", "substituted", "wrong-key", "malformed"})
  {
    for (size_t target : {0, 1, 2})
    {
      INFO("Directory fault " << fault << ", page " << target);
      ccf::tasks::JobBoard board;
      auto lfs = std::make_shared<CountingLFS>(board);
      ccf::AbstractNodeContext context;
      context.install_subsystem(lfs);
      ccf::indexing::LazyStrategy<SparseBucketTestIndex> index(
        map_a, context, 10, 1);
      for (size_t bucket = 0; bucket <= 4 * 256; ++bucket)
      {
        index.write(bucket * 20 + 1, "key");
        index.write(bucket * 20 + 1, "other");
      }
      const auto watermark = index.get_indexed_watermark();
      index.extend_index_to(watermark);
      REQUIRE(lfs->page_stores.size() == 8);
      flush_lfs(board);
      const auto page_key = lfs->page_stores[target * 2];
      const auto path =
        std::filesystem::path(".index") / CountingLFS::obfuscate_key(page_key);
      if (std::string(fault) == "missing")
      {
        REQUIRE(std::filesystem::remove(path));
      }
      else if (std::string(fault) == "corrupt")
      {
        auto contents = read_file(path);
        write_file_corrupted_at(path, contents.size() - 1, contents);
      }
      else if (std::string(fault) == "malformed")
      {
        lfs->store(page_key, {0});
        flush_lfs(board);
      }
      else
      {
        const auto replacement = std::string(fault) == "wrong-key" ?
          lfs->page_stores[target * 2 + 1] :
          lfs->page_stores[((target + 1) % 4) * 2];
        REQUIRE(std::filesystem::copy_file(
          std::filesystem::path(".index") /
            CountingLFS::obfuscate_key(replacement),
          path,
          std::filesystem::copy_options::overwrite_existing));
      }
      auto result = index.get_write_txs_in_range("key", 10, 10);
      index.tick();
      for (size_t retry = 0;
           index.get_indexed_watermark().seqno != 0 && retry < 5;
           ++retry)
      {
        REQUIRE_FALSE(result.has_value());
        REQUIRE(flush_lfs(board) > 0);
        result = index.get_write_txs_in_range("key", 10, 10);
        index.tick();
      }
      REQUIRE_FALSE(result.has_value());
      REQUIRE(index.get_indexed_watermark() == ccf::TxID());
      CHECK(index.next_requested() == 1);
      CHECK_FALSE(index.get_write_txs_in_range("other", 1, 1).has_value());
      for (size_t bucket = 0; bucket <= 4 * 256; ++bucket)
      {
        index.write(bucket * 20 + 1, "key");
        index.write(bucket * 20 + 1, "other");
      }
      result = index.get_write_txs_in_range("key", 10, 10);
      for (size_t retry = 0; !result.has_value() && retry < 5; ++retry)
      {
        REQUIRE(flush_lfs(board) > 0);
        result = index.get_write_txs_in_range("key", 10, 10);
      }
      REQUIRE(check_seqnos({}, result));
      CHECK_FALSE(index.next_requested().has_value());
    }
  }
}

TEST_CASE(
  "Sparse bucket sealed directory requires data" * doctest::test_suite("lfs"))
{
  for (bool corrupt : {false, true})
  {
    ccf::tasks::JobBoard board;
    auto lfs = std::make_shared<CountingLFS>(board);
    ccf::AbstractNodeContext context;
    context.install_subsystem(lfs);
    SparseBucketTestIndex index(map_a, context, 10, 4);
    for (size_t bucket = 0; bucket <= 256; ++bucket)
    {
      index.write(bucket * 20 + 1, "key");
    }
    flush_lfs(board);
    const auto path = std::filesystem::path(".index") /
      CountingLFS::obfuscate_key(lfs->data_stores[0]);
    if (corrupt)
    {
      auto contents = read_file(path);
      write_file_corrupted_at(path, contents.size() - 1, contents);
    }
    else
    {
      REQUIRE(std::filesystem::remove(path));
    }
    auto result = index.get_write_txs_in_range("key", 0, 21);
    index.tick();
    REQUIRE(lfs->data_fetches.size() == 3);
    for (size_t retry = 0;
         index.get_indexed_watermark().seqno != 0 && retry < 3;
         ++retry)
    {
      REQUIRE_FALSE(result.has_value());
      REQUIRE(flush_lfs(board) > 0);
      result = index.get_write_txs_in_range("key", 0, 21);
      index.tick();
    }
    REQUIRE_FALSE(result.has_value());
    CHECK(lfs->page_fetches.size() == 1);
    CHECK(index.get_indexed_watermark() == ccf::TxID());
  }
}

TEST_CASE(
  "Sparse bucket directory configuration identity" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  SparseBucketTestIndex small(map_a, context, 10, 4);
  SparseBucketTestIndex large(map_a, context, 20, 4);
  for (size_t bucket = 0; bucket <= 256; ++bucket)
  {
    small.write(bucket * 20 + 1, "key");
    large.write(bucket * 40 + 1, "key");
  }
  REQUIRE(lfs->page_stores.size() == 2);
  CHECK(lfs->page_stores[0] != lfs->page_stores[1]);
  flush_lfs(board);
  // Metadata for a different bucket-size configuration must not prove a false
  // gap for a file required by this configuration.
  REQUIRE(std::filesystem::remove(
    std::filesystem::path(".index") /
    CountingLFS::obfuscate_key(lfs->data_stores[2])));
  auto result = small.get_write_txs_in_range("key", 21, 21);
  small.tick();
  for (size_t retry = 0; small.get_indexed_watermark().seqno != 0 && retry < 3;
       ++retry)
  {
    REQUIRE_FALSE(result.has_value());
    flush_lfs(board);
    result = small.get_write_txs_in_range("key", 21, 21);
    small.tick();
  }
  REQUIRE_FALSE(result.has_value());
  CHECK(small.get_indexed_watermark() == ccf::TxID());
  result = large.get_write_txs_in_range("key", 41, 41);
  flush_lfs(board);
  REQUIRE(check_seqnos({41}, large.get_write_txs_in_range("key", 41, 41)));
}

TEST_CASE(
  "Sparse bucket inconsistent directory rebuilds" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  SparseBucketTestIndex index(map_a, context, 10, 101);
  for (size_t bucket = 0; bucket < 256; ++bucket)
  {
    index.write(bucket * 20 + 1, "key");
  }
  index.write(20'001, "key");
  REQUIRE(lfs->page_stores.size() == 1);
  flush_lfs(board);

  // Inject authenticated but inconsistent metadata through the trusted test
  // writer. The host cannot forge this; it exercises an internal invariant
  // failure without mistaking it for an ordinary missing data bucket.
  ccf::indexing::LFSContents contents(
    sizeof(size_t) + 256 * sizeof(ccf::SeqNo));
  auto* data = contents.data();
  auto size = contents.size();
  serialized::write<size_t>(data, size, 256);
  for (size_t bucket = 0; bucket < 256; ++bucket)
  {
    serialized::write<ccf::SeqNo>(
      data, size, bucket == 255 ? 6000 : bucket * 20);
  }
  const auto page_key = lfs->page_stores.front();
  lfs->store(page_key, std::move(contents));
  flush_lfs(board);

  auto result = index.get_write_txs_in_range("key", 5090, 6000);
  for (size_t retry = 0; retry < 2; ++retry)
  {
    REQUIRE_FALSE(result.has_value());
    REQUIRE(flush_lfs(board) > 0);
    result = index.get_write_txs_in_range("key", 5090, 6000);
  }
  REQUIRE_FALSE(result.has_value());
  // Fail closed until the serialized indexing tick performs the reset.
  CHECK(index.get_indexed_watermark().seqno == 20'001);
  CHECK_FALSE(index.get_write_txs_in_range("key", 20'001, 20'001).has_value());
  index.tick();
  CHECK(index.get_indexed_watermark() == ccf::TxID());
  CHECK(index.next_requested() == 1);
}

TEST_CASE("Sparse bucket single-slot cache" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  auto lfs = std::make_shared<CountingLFS>(board);
  ccf::AbstractNodeContext context;
  context.install_subsystem(lfs);
  SparseBucketTestIndex index(map_a, context, 10, 1);
  CHECK(index.max_requestable_range() == 0);
  index.write(1, "chain");
  index.write(10, "chain");
  index.write(1000, "chain");
  CHECK(
    check_seqnos({1000}, index.get_write_txs_in_range("chain", 1000, 1000)));
  CHECK_THROWS(index.get_write_txs_in_range("chain", 0, 1));
  auto result = index.get_write_txs_in_range("chain", 1, 1);
  for (size_t retry = 0; !result.has_value() && retry < 3; ++retry)
  {
    REQUIRE(flush_lfs(board) > 0);
    result = index.get_write_txs_in_range("chain", 1, 1);
  }
  CHECK(check_seqnos({1}, result));
}
