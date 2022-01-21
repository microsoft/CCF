// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "indexing/caching/enclave_cache.h"
#include "indexing/caching/host_cache.h"
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

TEST_CASE("Basic cache" * doctest::test_suite("blobcache"))
{
  messaging::BufferProcessor host_bp("blobcache_host");
  messaging::BufferProcessor enclave_bp("blobcache_enclave");

  constexpr size_t buf_size = 1 << 10;
  auto inbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader inbound_reader(inbound_buffer->bd);
  auto outbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader outbound_reader(outbound_buffer->bd);

  using namespace ccf::indexing::caching;

  HostCache hc(
    host_bp.get_dispatcher(),
    std::make_shared<ringbuffer::Writer>(inbound_reader));

  EnclaveCache ec(
    enclave_bp.get_dispatcher(),
    std::make_shared<ringbuffer::Writer>(outbound_reader));

  BlobKey key_a("Blob A");
  BlobContents blob_a{0, 1, 2, 3, 4, 5, 6, 7};

  BlobKey key_b("Blob B");
  BlobContents blob_b{'a', 'b', 'c'};

  ec.store(key_a, BlobContents(blob_a));
  ec.store(key_b, BlobContents(blob_b));

  REQUIRE(2 == host_bp.read_all(outbound_reader));

  {
    INFO("Load entries");

    auto result_a = ec.fetch(key_a);
    REQUIRE(result_a->fetch_result == FetchResult::Fetching);

    auto result_b = ec.fetch(key_b);
    REQUIRE(result_b->fetch_result == FetchResult::Fetching);

    host_bp.read_all(outbound_reader);
    enclave_bp.read_all(inbound_reader);

    REQUIRE(result_a->fetch_result == FetchResult::Loaded);
    REQUIRE(result_a->contents == blob_a);

    REQUIRE(result_b->fetch_result == FetchResult::Loaded);
    REQUIRE(result_b->contents == blob_b);
  }

  {
    INFO("Host cache provides wrong file");
    REQUIRE(std::filesystem::copy_file(
      hc.root_dir / obfuscate_key(key_b),
      hc.root_dir / obfuscate_key(key_a),
      std::filesystem::copy_options::overwrite_existing));

    auto result = ec.fetch(key_a);

    host_bp.read_all(outbound_reader);
    enclave_bp.read_all(inbound_reader);

    REQUIRE(result->fetch_result == FetchResult::Corrupt);
    REQUIRE(result->contents != blob_a);
  }

#ifndef PLAINTEXT_CACHE
  {
    INFO("Host cache provides corrupt file");
    const auto b_path = hc.root_dir / obfuscate_key(key_b);
    const auto original_b_contents = read_file(b_path);

    for (auto i = 0; i < original_b_contents.size(); ++i)
    {
      write_file_corrupted_at(b_path, i, original_b_contents);

      auto result = ec.fetch(key_b);

      host_bp.read_all(outbound_reader);
      enclave_bp.read_all(inbound_reader);

      REQUIRE(result->fetch_result == FetchResult::Corrupt);
      REQUIRE(result->contents != blob_b);
    }
  }
#endif
}

TEST_CASE("Integrated cache" * doctest::test_suite("blobcache"))
{
  kv::Store kv_store;

  auto consensus = std::make_shared<AllCommittableConsensus>();
  kv_store.set_consensus(consensus);

  auto fetcher = std::make_shared<TestTransactionFetcher>();
  ccf::indexing::Indexer indexer(fetcher);

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  messaging::BufferProcessor host_bp("blobcache_host");
  messaging::BufferProcessor enclave_bp("blobcache_enclave");

  constexpr size_t buf_size = 1 << 16;
  auto inbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader inbound_reader(inbound_buffer->bd);
  auto outbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);

  ringbuffer::Reader outbound_reader(outbound_buffer->bd);
  ccf::indexing::caching::HostCache hc(
    host_bp.get_dispatcher(),
    std::make_shared<ringbuffer::Writer>(inbound_reader));
  ccf::indexing::caching::EnclaveCache ec(
    enclave_bp.get_dispatcher(),
    std::make_shared<ringbuffer::Writer>(outbound_reader));

  auto flush_ringbuffers = [&]() {
    return host_bp.read_all(outbound_reader) +
      enclave_bp.read_all(inbound_reader);
  };

  using StratA = ccf::indexing::strategies::SeqnosByKeyAsync<decltype(map_a)>;
  auto index_a = std::make_shared<StratA>(map_a, ec);
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

  const auto current_seqno = kv_store.current_version();
  const auto max_requestable = index_a->max_requestable_range();
  const auto request_range = max_requestable / 3;

  {
    INFO("Requestable range is limited");

    REQUIRE_THROWS(index_a->get_all_write_txs("hello"));
    REQUIRE_THROWS(
      index_a->get_write_txs_in_range("hello", 0, max_requestable + 1));
    REQUIRE_THROWS(index_a->get_write_txs_in_range(
      "hello", current_seqno - (max_requestable + 1), current_seqno));

    REQUIRE(flush_ringbuffers() == 0);
  }

  auto fetch_all = [&](const auto& key, const auto& expected) {
    auto range_start = 0;
    auto range_end = request_range;

    while (true)
    {
      LOG_INFO_FMT("Fetching {} from {} to {}", key, range_start, range_end);

      auto results =
        index_a->get_write_txs_in_range(key, range_start, range_end);

      if (!results.has_value())
      {
        // This required an async load from disk
        REQUIRE(flush_ringbuffers() > 0);

        results = index_a->get_write_txs_in_range(key, range_start, range_end);
        REQUIRE(results.has_value());
      }

      REQUIRE(check_seqnos(expected, results, false));

      if (range_end == current_seqno)
      {
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

    fetch_all("hello", seqnos_hello);
    fetch_all("saluton", seqnos_saluton);
  }

  // INFO(
  //   "Indexes can be installed later, and will be populated after enough "
  //   "ticks");

  // auto index_b = std::make_shared<IndexB>(map_b);
  // REQUIRE(indexer.install_strategy(index_b));
  // REQUIRE_FALSE(indexer.install_strategy(index_b));

  // auto current_ = kv_store.current_txid();
  // ccf::TxID current{current_.term, current_.version};
  // REQUIRE(index_a->get_indexed_watermark() == current);
  // REQUIRE(index_b->get_indexed_watermark() == ccf::TxID());

  // tick_until_caught_up();

  // REQUIRE(index_a->get_indexed_watermark() == current);
  // REQUIRE(index_b->get_indexed_watermark() == current);

  // run_tests(
  //   tick_until_caught_up,
  //   kv_store,
  //   indexer,
  //   seqnos_hello,
  //   seqnos_saluton,
  //   seqnos_1,
  //   seqnos_2,
  //   index_a,
  //   index_b);
}
