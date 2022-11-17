// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_bucketed.h"
#include "host/lfs_file_handler.h"
#include "indexing/enclave_lfs_access.h"
#include "indexing/test/common.h"

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

void write_file_corrupted_at(
  const std::filesystem::path& p,
  size_t i,
  const std::vector<uint8_t>& original)
{
  auto corrupted(original);
  REQUIRE(i < corrupted.size());
  corrupted[i]++;
  std::ofstream f(p, std::ios::trunc | std::ios::binary);
  f.write((char const*)corrupted.data(), corrupted.size());
  f.close();
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
  actions.push_back({seqnos_hello, [](size_t i, kv::Tx& tx) {
                       tx.wo(map_a)->put("hello", "value doesn't matter");
                       return true;
                     }});
  actions.push_back({seqnos_saluton, [](size_t i, kv::Tx& tx) {
                       if (i % 2 == 0)
                       {
                         tx.wo(map_a)->put("saluton", "value doesn't matter");
                         return true;
                       }
                       return false;
                     }});
  actions.push_back({seqnos_1, [](size_t i, kv::Tx& tx) {
                       if (i % 3 == 0)
                       {
                         tx.wo(map_b)->put(1, 42);
                         return true;
                       }
                       return false;
                     }});
  actions.push_back({seqnos_2, [](size_t i, kv::Tx& tx) {
                       if (i % 4 == 0)
                       {
                         tx.wo(map_b)->put(2, 42);
                         return true;
                       }
                       return false;
                     }});
  actions.push_back({seqnos_set, [](size_t i, kv::Tx& tx) {
                       if (i % 5 == 0)
                       {
                         tx.wo(set_a)->insert("set key");
                         return true;
                       }
                       return false;
                     }});
  actions.push_back({seqnos_value, [](size_t i, kv::Tx& tx) {
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
  messaging::BufferProcessor host_bp("lfs_host");
  messaging::BufferProcessor enclave_bp("lfs_enclave");

  constexpr size_t buf_size = 1 << 10;
  auto inbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader inbound_reader(inbound_buffer->bd);
  auto outbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader outbound_reader(outbound_buffer->bd);

  asynchost::LFSFileHandler host_files(
    std::make_shared<ringbuffer::Writer>(inbound_reader));
  host_files.register_message_handlers(host_bp.get_dispatcher());

  ccf::indexing::EnclaveLFSAccess enclave_lfs(
    std::make_shared<ringbuffer::Writer>(outbound_reader));
  enclave_lfs.register_message_handlers(enclave_bp.get_dispatcher());

  ccf::indexing::LFSKey key_a("Blob A");
  ccf::indexing::LFSContents blob_a{0, 1, 2, 3, 4, 5, 6, 7};

  ccf::indexing::LFSKey key_b("Blob B");
  ccf::indexing::LFSContents blob_b{'a', 'b', 'c'};

  enclave_lfs.store(key_a, ccf::indexing::LFSContents(blob_a));
  enclave_lfs.store(key_b, ccf::indexing::LFSContents(blob_b));

  REQUIRE(2 == host_bp.read_all(outbound_reader));

  {
    INFO("Load entries");

    auto result_a = enclave_lfs.fetch(key_a);
    REQUIRE(result_a->fetch_result == ccf::indexing::FetchResult::Fetching);

    auto result_b = enclave_lfs.fetch(key_b);
    REQUIRE(result_b->fetch_result == ccf::indexing::FetchResult::Fetching);

    host_bp.read_all(outbound_reader);
    enclave_bp.read_all(inbound_reader);

    REQUIRE(result_a->fetch_result == ccf::indexing::FetchResult::Loaded);
    REQUIRE(result_a->contents == blob_a);

    REQUIRE(result_b->fetch_result == ccf::indexing::FetchResult::Loaded);
    REQUIRE(result_b->contents == blob_b);
  }

  {
    INFO("Host cache provides wrong file");
    REQUIRE(std::filesystem::copy_file(
      host_files.root_dir /
        ccf::indexing::EnclaveLFSAccess::obfuscate_key(key_b),
      host_files.root_dir /
        ccf::indexing::EnclaveLFSAccess::obfuscate_key(key_a),
      std::filesystem::copy_options::overwrite_existing));

    auto result = enclave_lfs.fetch(key_a);

    host_bp.read_all(outbound_reader);
    enclave_bp.read_all(inbound_reader);

    REQUIRE(result->fetch_result == ccf::indexing::FetchResult::Corrupt);
    REQUIRE(result->contents != blob_a);
  }

#ifndef PLAINTEXT_CACHE
  {
    INFO("Host cache provides corrupt file");
    const auto b_path = host_files.root_dir /
      ccf::indexing::EnclaveLFSAccess::obfuscate_key(key_b);
    const auto original_b_contents = read_file(b_path);

    for (auto i = 0; i < original_b_contents.size(); ++i)
    {
      write_file_corrupted_at(b_path, i, original_b_contents);

      auto result = enclave_lfs.fetch(key_b);

      host_bp.read_all(outbound_reader);
      enclave_bp.read_all(inbound_reader);

      REQUIRE(result->fetch_result == ccf::indexing::FetchResult::Corrupt);
      REQUIRE(result->contents != blob_b);
    }
  }
#endif
}

TEST_CASE("Integrated cache" * doctest::test_suite("lfs"))
{
  kv::Store kv_store;

  auto consensus = std::make_shared<AllCommittableConsensus>();
  kv_store.set_consensus(consensus);

  auto fetcher = std::make_shared<TestTransactionFetcher>();
  ccf::indexing::Indexer indexer(fetcher);

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  messaging::BufferProcessor host_bp("lfs_host");
  messaging::BufferProcessor enclave_bp("lfs_enclave");

  constexpr size_t buf_size = 1 << 16;
  auto inbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader inbound_reader(inbound_buffer->bd);
  auto outbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);

  ringbuffer::Reader outbound_reader(outbound_buffer->bd);
  asynchost::LFSFileHandler host_files(
    std::make_shared<ringbuffer::Writer>(inbound_reader));
  host_files.register_message_handlers(host_bp.get_dispatcher());

  auto enclave_lfs = std::make_shared<ccf::indexing::EnclaveLFSAccess>(
    std::make_shared<ringbuffer::Writer>(outbound_reader));
  enclave_lfs->register_message_handlers(enclave_bp.get_dispatcher());

  ccfapp::AbstractNodeContext node_context;
  node_context.install_subsystem(enclave_lfs);

  auto flush_ringbuffers = [&]() {
    return host_bp.read_all(outbound_reader) +
      enclave_bp.read_all(inbound_reader);
  };

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

  static constexpr auto num_transactions =
    ccf::indexing::Indexer::MAX_REQUESTABLE * 3;
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

      flush_ringbuffers();
    }
  };

  tick_until_caught_up();
  REQUIRE(flush_ringbuffers() == 0);

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

    REQUIRE(flush_ringbuffers() == 0);
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

      if (!results.has_value())
      {
        // This required an async load from disk
        REQUIRE(flush_ringbuffers() > 0);

        results = strat->get_write_txs_in_range(key, range_start, range_end);

        if (should_fail && !results.has_value())
        {
          // Ringbuffer flush was insufficient to fill the requested range.
          // Likely a corrupted or missing file, which needs a full re-index to
          // resolve
          return;
        }
        else
        {
          REQUIRE(results.has_value());
        }
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

      if (!results.has_value())
      {
        // This required an async load from disk
        REQUIRE(flush_ringbuffers() > 0);

        results = strat->get_write_txs_in_range(range_start, range_end);

        if (should_fail && !results.has_value())
        {
          // Ringbuffer flush was insufficient to fill the requested range.
          // Likely a corrupted or missing file, which needs a full re-index to
          // resolve
          return;
        }
        else
        {
          REQUIRE(results.has_value());
        }
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

  kv::TxID current_ = kv_store.current_txid();
  ccf::TxID current{current_.term, current_.version};
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

    current_ = kv_store.current_txid();
    current = {current_.term, current_.version};
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

      // index_a has seen a missing file and reset, but index_b hasn't (yet)
      REQUIRE(index_a->get_indexed_watermark() != current);
      REQUIRE(index_b->get_indexed_watermark() == current);

      fetch_all(index_b, 1, seqnos_1, true);
      fetch_all(index_set, "set key", seqnos_set, true);
      fetch_all_value(index_value, seqnos_value, true);

      // Now index_b has also seen a missing file
      REQUIRE(index_b->get_indexed_watermark() != current);

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
      for (auto const& f :
           std::filesystem::directory_iterator(host_files.root_dir))
      {
        std::filesystem::remove(f);
      }

      identify_error_and_reindex();
    }

    {
      INFO("Corrupted files");
      for (auto const& f :
           std::filesystem::directory_iterator(host_files.root_dir))
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
  kv::Store kv_store;

  auto consensus = std::make_shared<AllCommittableConsensus>();
  kv_store.set_consensus(consensus);

  auto fetcher = std::make_shared<TestTransactionFetcher>();
  ccf::indexing::Indexer indexer(fetcher);

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  messaging::BufferProcessor host_bp("lfs_host");
  messaging::BufferProcessor enclave_bp("lfs_enclave");

  constexpr size_t buf_size = 1 << 16;
  auto inbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader inbound_reader(inbound_buffer->bd);
  auto outbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);

  ringbuffer::Reader outbound_reader(outbound_buffer->bd);
  asynchost::LFSFileHandler host_files(
    std::make_shared<ringbuffer::Writer>(inbound_reader));
  host_files.register_message_handlers(host_bp.get_dispatcher());

  auto enclave_lfs = std::make_shared<ccf::indexing::EnclaveLFSAccess>(
    std::make_shared<ringbuffer::Writer>(outbound_reader));
  enclave_lfs->register_message_handlers(enclave_bp.get_dispatcher());

  ccfapp::AbstractNodeContext node_context;
  node_context.install_subsystem(enclave_lfs);

  auto flush_ringbuffers = [&]() {
    return host_bp.read_all(outbound_reader) +
      enclave_bp.read_all(inbound_reader);
  };

  using Strat =
    ccf::indexing::strategies::SeqnosByKey_Bucketed<decltype(map_b)>;
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
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
      const auto seqno = tx.get_txid()->version;
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
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
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

      flush_ringbuffers();
    }
  };

  tick_until_caught_up();
  REQUIRE(flush_ringbuffers() == 0);

  auto fetch_write_seqnos = [&](size_t key) {
    const auto max_range = index->max_requestable_range();
    const auto end_seqno = kv_store.get_txid().seqno;

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

      if (!results.has_value())
      {
        // This required an async load from disk
        REQUIRE(flush_ringbuffers() > 0);

        results = index->get_write_txs_in_range(key, range_start, range_end);
        REQUIRE(results.has_value());
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