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
    enclave_bp.get_dispatcher(),
    std::make_shared<ringbuffer::Writer>(outbound_reader));

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

  ccf::indexing::EnclaveLFSAccess enclave_lfs(
    enclave_bp.get_dispatcher(),
    std::make_shared<ringbuffer::Writer>(outbound_reader));

  auto flush_ringbuffers = [&]() {
    return host_bp.read_all(outbound_reader) +
      enclave_bp.read_all(inbound_reader);
  };

  using StratA =
    ccf::indexing::strategies::SeqnosByKey_Bucketed<decltype(map_a)>;
  auto index_a = std::make_shared<StratA>(map_a, enclave_lfs);
  REQUIRE(indexer.install_strategy(index_a));

  static constexpr auto num_transactions =
    ccf::indexing::Indexer::MAX_REQUESTABLE * 3;
  ExpectedSeqNos seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2;
  create_transactions(
    kv_store, seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2);

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
      LOG_TRACE_FMT("Fetching {} from {} to {}", key, range_start, range_end);

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
  auto index_b = std::make_shared<StratB>(map_b, enclave_lfs);
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
    REQUIRE(create_transactions(
      kv_store, seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2));

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
  }

  {
    INFO("Invalid disk cache leads to index being rebuilt");

    auto identify_error_and_reindex = [&]() {
      fetch_all(index_a, "hello", seqnos_hello, true);

      // index_a has seen a missing file and reset, but index_b hasn't (yet)
      REQUIRE(index_a->get_indexed_watermark() != current);
      REQUIRE(index_b->get_indexed_watermark() == current);

      fetch_all(index_b, 1, seqnos_1, true);

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
