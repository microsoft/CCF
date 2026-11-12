// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_sorted.h"
#include "ds/serialized.h"
#include "indexing/enclave_lfs_access.h"
#include "indexing/test/common.h"

#include <doctest/doctest.h>
#include <functional>
#include <future>
#include <limits>

namespace
{
  using State = ccf::indexing::FetchResult::FetchResultType;
  using Options = ccf::indexing::strategies::SortedIndexOptions;
  using Sorted = ccf::indexing::strategies::SeqnosByKey_Sorted<MapA>;

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

  std::vector<uint8_t> read_file(const std::filesystem::path& path)
  {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    REQUIRE(f.good());
    const auto length = f.tellg();
    REQUIRE(length >= 0);
    std::vector<uint8_t> contents(static_cast<size_t>(length));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(contents.data()), contents.size());
    REQUIRE(f.good());
    return contents;
  }

  void write_file(
    const std::filesystem::path& path, const std::vector<uint8_t>& contents)
  {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    f.close();
    REQUIRE(f.good());
  }

  class ObservedStorage : public ccf::indexing::EnclaveLFSAccess
  {
  public:
    using EnclaveLFSAccess::EnclaveLFSAccess;
    std::atomic<size_t> fetches = 0;
    bool fail_next_write = false;
    std::filesystem::path failed_write;
    std::function<void(ccf::indexing::LFSContents&)> mutate_next_write;

    void store(
      const ccf::indexing::LFSKey& key,
      ccf::indexing::LFSContents&& contents) override
    {
      if (mutate_next_write)
      {
        auto mutate = mutate_next_write;
        mutate_next_write = {};
        mutate(contents);
      }
      if (fail_next_write)
      {
        failed_write = std::filesystem::path(".index") / filename(key);
        std::filesystem::create_directory(failed_write);
        fail_next_write = false;
      }
      EnclaveLFSAccess::store(key, std::move(contents));
    }

    ccf::indexing::FetchResultPtr fetch(
      const ccf::indexing::LFSKey& key) override
    {
      ++fetches;
      return EnclaveLFSAccess::fetch(key);
    }
  };

  struct Harness
  {
    ccf::tasks::JobBoard board;
    ccf::AbstractNodeContext context;
    std::shared_ptr<ObservedStorage> storage =
      std::make_shared<ObservedStorage>(board);
    Options options;
    std::shared_ptr<Sorted> index;
    size_t ticks = 0;
    size_t peak_buffer = 0;
    ccf::SeqNo seqno = 0;

    explicit Harness(const Options& opts = {512, 128, 32768, 3}) : options(opts)
    {
      context.install_subsystem(storage);
      index = std::make_shared<Sorted>(map_a, context, options);
    }

    void step()
    {
      REQUIRE(++ticks < 300000);
      index->tick();
      const auto stats = index->describe();
      peak_buffer = std::max(peak_buffer, stats["buffer_bytes"].get<size_t>());
      REQUIRE(stats["runs"].get<size_t>() <= 64);
      REQUIRE(stats["retired_runs"].get<size_t>() <= 68);
      REQUIRE(
        stats["cache_reserved_bytes"].get<size_t>() <=
        options.query_cache_bytes);
      const auto decoded_limit =
        stats["decoded_block_limit_bytes"].get<size_t>();
      REQUIRE(
        stats["merge_input_decoded_bytes"].get<size_t>() <= 2 * decoded_limit);
      REQUIRE(
        stats["compaction_output_bytes"].get<size_t>() <= options.block_bytes);
      REQUIRE(
        stats["compaction_output_decoded_bytes"].get<size_t>() <=
        decoded_limit);
      flush_lfs(board);
    }

    void settle()
    {
      while (index->describe()["busy"].get<bool>())
      {
        step();
      }
    }

    void submit(const std::vector<std::string>& keys, ccf::SeqNo at = 0)
    {
      settle();
      auto store = std::make_shared<ccf::kv::Store>();
      store->set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
      auto tx = store->create_tx();
      for (const auto& k : keys)
      {
        tx.wo(map_a)->put(k, "value");
      }
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      seqno = at == 0 ? seqno + 1 : at;
      index->handle_committed_transaction({1, seqno}, store);
    }

    void append(const std::vector<std::string>& keys, ccf::SeqNo at = 0)
    {
      submit(keys, at);
      settle();
      REQUIRE(index->get_indexed_watermark().seqno == seqno);
    }

    ccf::SeqNoCollection query(
      const std::string& k, ccf::SeqNo from, ccf::SeqNo to)
    {
      auto result = index->get_write_txs_in_range(k, from, to);
      for (size_t attempts = 0; !result; ++attempts)
      {
        REQUIRE(attempts < 1000);
        step();
        result = index->get_write_txs_in_range(k, from, to);
      }
      return *result;
    }

    size_t disk_bytes() const
    {
      size_t bytes = 0;
      for (const auto& entry : std::filesystem::directory_iterator(".index"))
      {
        bytes += entry.file_size();
      }
      return bytes;
    }
  };
}

TEST_CASE("Authenticated plaintext files" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  ccf::indexing::EnclaveLFSAccess storage(board);
  const ccf::indexing::LFSContents payload{'p', 'u', 'b', 'l', 'i', 'c'};
  storage.store("run1:block0", ccf::indexing::LFSContents(payload));
  auto initial = storage.fetch("run1:block0");
  REQUIRE(initial->fetch_result == State::Fetching);
  flush_lfs(board);
  REQUIRE(initial->fetch_result == State::Loaded);
  CHECK(initial->contents == payload);

  const auto path = std::filesystem::path(".index") /
    ccf::indexing::EnclaveLFSAccess::filename("run1:block0");
  const auto original = read_file(path);
  CHECK(std::equal(payload.begin(), payload.end(), original.begin()));
  CHECK(original.size() == payload.size() + 32);
  const auto fetch = [&]() {
    auto result = storage.fetch("run1:block0");
    flush_lfs(board);
    return result;
  };

  SUBCASE("Every truncated length is rejected")
  {
    for (size_t size = 0; size < original.size(); ++size)
    {
      write_file(path, {original.begin(), original.begin() + size});
      CHECK(fetch()->fetch_result == State::Corrupt);
    }
  }
  SUBCASE("Every modified byte is rejected")
  {
    for (size_t i = 0; i < original.size(); ++i)
    {
      auto bad = original;
      bad[i] ^= 1;
      write_file(path, bad);
      CHECK(fetch()->fetch_result == State::Corrupt);
    }
  }
  SUBCASE("Zeroed file is rejected")
  {
    write_file(path, std::vector<uint8_t>(original.size(), 0));
    CHECK(fetch()->fetch_result == State::Corrupt);
  }
  SUBCASE("Identity substitution is rejected")
  {
    storage.store("run2:block0", ccf::indexing::LFSContents(payload));
    flush_lfs(board);
    const auto other = std::filesystem::path(".index") /
      ccf::indexing::EnclaveLFSAccess::filename("run2:block0");
    write_file(path, read_file(other));
    CHECK(fetch()->fetch_result == State::Corrupt);
  }
  SUBCASE("Oversized host file is rejected before allocation")
  {
    std::filesystem::resize_file(path, uintmax_t(1) << 40);
    CHECK(fetch()->fetch_result == State::Corrupt);
  }
  SUBCASE("Deletion is ordered after writes and before subsequent fetches")
  {
    storage.store("run1:block0", ccf::indexing::LFSContents(payload));
    storage.remove("run1:block0");
    CHECK(fetch()->fetch_result == State::NotFound);
  }
  SUBCASE("Failed write cannot be fetched as successful data")
  {
    std::filesystem::remove(path);
    std::filesystem::create_directory(path);
    storage.store("run1:block0", ccf::indexing::LFSContents(payload));
    CHECK(fetch()->fetch_result != State::Loaded);
  }
}

TEST_CASE("Sorted sparse entries and gaps" * doctest::test_suite("lfs"))
{
  Harness h;
  h.append({"early"});
  const auto bytes = h.disk_bytes();
  h.append({"late"}, 1'000'000'000'000);
  CHECK(h.disk_bytes() == bytes);
  CHECK(check_seqnos({1}, h.query("early", 0, h.seqno)));
  CHECK(check_seqnos({h.seqno}, h.query("late", 0, h.seqno)));
  CHECK(h.query("late", 0, h.seqno - 1).empty());
  CHECK(h.query("absent", 0, h.seqno).empty());
  CHECK_FALSE(h.index->get_write_txs_in_range("absent", 0, h.seqno + 1));
  CHECK_THROWS(h.index->get_write_txs_in_range("early", 2, 1));
}

TEST_CASE("Sorted hot and distinct keys" * doctest::test_suite("lfs"))
{
  Harness h;
  ExpectedSeqNos hot;
  for (size_t i = 0; i < 256; ++i)
  {
    h.append({"hot", fmt::format("key{:04}", i)});
    hot.insert(h.seqno);
  }
  CHECK(check_seqnos(hot, h.query("hot", 0, h.seqno)));
  for (size_t i = 0; i < 256; ++i)
  {
    CHECK(
      check_seqnos({i + 1}, h.query(fmt::format("key{:04}", i), 0, h.seqno)));
  }
  CHECK(h.query("absent", 0, h.seqno).empty());
  CHECK(h.query("hot", 0, 0).empty());
  CHECK(check_seqnos({64, 65, 66}, h.query("hot", 64, 66)));
  CHECK(h.index->describe()["compactions"].get<size_t>() > 10);
  CHECK(h.index->describe()["runs"].get<size_t>() < 10);
  CHECK(h.peak_buffer <= 512 + 2 * 128);
  CHECK(h.disk_bytes() < 512 * 160);
}

TEST_CASE(
  "Sorted cache shares reads without retaining query state" *
  doctest::test_suite("lfs"))
{
  Harness h;
  for (size_t i = 0; i < 32; ++i)
  {
    h.append({"hot", fmt::format("key{:04}", i)});
  }
  const auto before = h.storage->fetches.load();
  CHECK_FALSE(h.index->get_write_txs_in_range("key0000", 1, 32));
  const auto pending_reads = h.storage->fetches.load();
  REQUIRE(pending_reads > before);
  for (size_t i = 0; i < 12; ++i)
  {
    CHECK_FALSE(
      h.index->get_write_txs_in_range(fmt::format("key{:04}", i), 1, 32));
  }
  // All requests share the pending boundary reads across the same runs.
  CHECK(h.storage->fetches == pending_reads);
  // The last request is not blocked behind the eleven abandoned requests.
  CHECK(check_seqnos({12}, h.query("key0011", 1, 32)));
  const auto fetched = h.storage->fetches.load();
  const auto decoded = h.index->describe()["query_block_decodes"];
  CHECK(check_seqnos({12}, h.query("key0011", 1, 32)));
  CHECK(h.storage->fetches == fetched);
  CHECK(h.index->describe()["query_block_decodes"] == decoded);
  CHECK_FALSE(h.index->describe().contains("queries"));
  CHECK_FALSE(h.index->describe().contains("query_result_entries"));
}

TEST_CASE(
  "Sorted packs blocks independently of maintenance work budget" *
  doctest::test_suite("lfs"))
{
  Harness h(Options{512, 128, 32768, 1});
  std::vector<std::string> keys;
  for (size_t i = 0; i < 200; ++i)
  {
    keys.push_back(fmt::format("key{:04}", i));
  }
  h.append(keys);
  const auto key_bytes =
    MapA::KeySerialiser::to_serialised(keys.front()).size();
  const auto entry_bytes =
    2 * sizeof(uint64_t) + key_bytes + sizeof(ccf::SeqNo);
  const auto per_block =
    (h.options.block_bytes - sizeof(uint64_t)) / entry_bytes;
  const auto expected_blocks = (keys.size() + per_block - 1) / per_block;
  CHECK(h.index->describe()["blocks_written"] == expected_blocks);
  size_t full = 0;
  size_t files = 0;
  for (const auto& file : std::filesystem::directory_iterator(".index"))
  {
    ++files;
    const auto payload = file.file_size() - 32;
    CHECK(payload <= h.options.block_bytes);
    if (payload == sizeof(uint64_t) + per_block * entry_bytes)
    {
      ++full;
    }
  }
  CHECK(files == expected_blocks);
  CHECK(full >= expected_blocks - 1);
}

TEST_CASE(
  "Sorted batches cold reads without returning partial results" *
  doctest::test_suite("lfs"))
{
  Harness h;
  for (size_t i = 0; i < 128; ++i)
  {
    h.append({"hot", fmt::format("key{:04}", i)});
  }
  CHECK(check_seqnos({64}, h.query("hot", 64, 64)));
  size_t largest_batch = 0;
  std::optional<ccf::SeqNoCollection> result;
  for (size_t retries = 0; !result; ++retries)
  {
    REQUIRE(retries < 20);
    const auto before = h.storage->fetches.load();
    result = h.index->get_write_txs_in_range("hot", 1, 128);
    const auto scheduled = h.storage->fetches.load() - before;
    largest_batch = std::max(largest_batch, scheduled);
    if (scheduled != 0)
    {
      CHECK_FALSE(result);
    }
    flush_lfs(h.board);
  }
  CHECK(result->size() == 128);
  CHECK(largest_batch >= 4);
}

TEST_CASE(
  "Sorted defaults use 64KiB blocks and 512 entries per tick" *
  doctest::test_suite("lfs"))
{
  const Options options;
  CHECK(options.block_bytes == 64 * 1024);
  CHECK(options.entries_per_tick == 512);
}

TEST_CASE(
  "Sorted repeated keys are encoded once per block group" *
  doctest::test_suite("lfs"))
{
  Harness h;
  for (size_t i = 0; i < 200; ++i)
  {
    h.append({"hot"});
  }
  const auto key = MapA::KeySerialiser::to_serialised("hot");
  size_t encoded_bytes = 0;
  size_t flat_bytes = 0;
  for (const auto& file : std::filesystem::directory_iterator(".index"))
  {
    auto contents = read_file(file.path());
    contents.resize(contents.size() - 32);
    const auto* data = contents.data();
    auto remaining = contents.size();
    const auto count = serialized::read<uint64_t>(data, remaining);
    const auto key_length = serialized::read<uint64_t>(data, remaining);
    REQUIRE(key_length == key.size());
    REQUIRE(remaining >= key_length);
    CHECK(std::equal(key.begin(), key.end(), data));
    serialized::skip(data, remaining, key_length);
    CHECK(serialized::read<uint64_t>(data, remaining) == count);
    CHECK(remaining == count * sizeof(ccf::SeqNo));
    encoded_bytes += contents.size();
    flat_bytes += sizeof(uint64_t) +
      count * (sizeof(uint64_t) + key.size() + sizeof(ccf::SeqNo));
  }
  CHECK(encoded_bytes * 4 < flat_bytes * 3);
  CHECK(h.query("hot", 1, 200).size() == 200);
}

TEST_CASE(
  "Sorted grouped long keys respect decoded memory limits" *
  doctest::test_suite("lfs"))
{
  Harness h;
  const std::string key(40, 'x');
  for (size_t i = 0; i < 100; ++i)
  {
    h.append({key});
  }
  const auto key_bytes = MapA::KeySerialiser::to_serialised(key).size();
  const auto decoded_limit =
    h.index->describe()["decoded_block_limit_bytes"].get<size_t>();
  const auto per_entry =
    sizeof(std::pair<ccf::ByteVector, ccf::SeqNo>) + key_bytes;
  for (const auto& file : std::filesystem::directory_iterator(".index"))
  {
    const auto contents = read_file(file.path());
    const auto* data = contents.data();
    auto remaining = contents.size() - 32;
    const auto count = serialized::read<uint64_t>(data, remaining);
    CHECK(count * per_entry <= decoded_limit);
  }
  CHECK(h.query(key, 1, 100).size() == 100);
}

TEST_CASE(
  "Malformed authenticated grouped blocks request rebuild" *
  doctest::test_suite("lfs"))
{
  Harness h;
  enum class Fault
  {
    EntryCount,
    ZeroGroup,
    ExcessGroup,
    TrailingData,
    DecodedExpansion
  };
  auto fault = Fault::EntryCount;
  SUBCASE("Entry count is rejected before reserve")
  {
    fault = Fault::EntryCount;
  }
  SUBCASE("Zero-length group cannot loop")
  {
    fault = Fault::ZeroGroup;
  }
  SUBCASE("Group exceeds declared entry count")
  {
    fault = Fault::ExcessGroup;
  }
  SUBCASE("Trailing data is rejected")
  {
    fault = Fault::TrailingData;
  }
  SUBCASE("Encoded payload fits but decoded keys exceed budget")
  {
    fault = Fault::DecodedExpansion;
  }
  bool injected = false;
  h.storage->mutate_next_write = [&](ccf::indexing::LFSContents& contents) {
    injected = true;
    if (fault == Fault::DecodedExpansion)
    {
      contents.resize(128);
      auto* data = contents.data();
      auto remaining = contents.size();
      serialized::write(data, remaining, uint64_t(8));
      serialized::write(data, remaining, uint64_t(40));
      const std::vector<uint8_t> key(40, 'x');
      serialized::write(data, remaining, key.data(), key.size());
      serialized::write(data, remaining, uint64_t(8));
      for (ccf::SeqNo i = 1; i <= 8; ++i)
      {
        serialized::write(data, remaining, i);
      }
      REQUIRE(remaining == 0);
    }
    else if (fault == Fault::TrailingData)
    {
      contents.push_back(0);
    }
    else
    {
      auto* data = contents.data();
      auto remaining = contents.size();
      if (fault == Fault::EntryCount)
      {
        serialized::write(
          data, remaining, std::numeric_limits<uint64_t>::max());
      }
      else
      {
        const auto* read = contents.data();
        auto read_remaining = contents.size();
        const auto count = serialized::read<uint64_t>(read, read_remaining);
        const auto length = serialized::read<uint64_t>(read, read_remaining);
        const auto offset = 2 * sizeof(uint64_t) + length;
        data += offset;
        remaining -= offset;
        serialized::write(
          data, remaining, fault == Fault::ZeroGroup ? uint64_t(0) : count + 1);
      }
    }
  };
  std::vector<std::string> keys;
  for (size_t i = 0; i < 20; ++i)
  {
    keys.push_back(fmt::format("key{:04}", i));
  }
  h.append(keys);
  REQUIRE(injected);
  for (size_t retries = 0; h.index->get_indexed_watermark().seqno != 0;
       ++retries)
  {
    REQUIRE(retries < 100);
    CHECK_FALSE(h.index->get_write_txs_in_range("", 0, 1));
    flush_lfs(h.board);
    CHECK_FALSE(h.index->get_write_txs_in_range("", 0, 1));
    h.step();
  }
  h.settle();
  CHECK(h.disk_bytes() == 0);
}

TEST_CASE(
  "Sorted cache limit is explicit and smaller requests recover" *
  doctest::test_suite("lfs"))
{
  Harness h(Options{512, 128, 8192, 3});
  for (size_t i = 0; i < 128; ++i)
  {
    h.append({"hot", fmt::format("key{:04}", i)});
  }
  CHECK_THROWS_AS(h.query("hot", 1, 128), std::length_error);
  CHECK(check_seqnos({64}, h.query("hot", 64, 64)));
  CHECK(h.query("zz-absent", 1, 128).empty());
  // Different requests evict blocks, not one another's retained results.
  for (size_t i = 0; i < 128; ++i)
  {
    CHECK(check_seqnos({i + 1}, h.query(fmt::format("key{:04}", i), 1, 128)));
  }
  CHECK(h.index->describe()["cache_reserved_bytes"].get<size_t>() <= 8192);
}

TEST_CASE(
  "Sorted ingests a whole transaction before flushing" *
  doctest::test_suite("lfs"))
{
  Harness h;
  std::vector<std::string> keys;
  for (size_t i = 0; i < 200; ++i)
  {
    keys.push_back(fmt::format("key{:04}", i));
  }
  h.submit(keys);
  REQUIRE(h.index->get_indexed_watermark().seqno == 1);
  CHECK(
    h.index->describe()["buffer_bytes"].get<size_t>() >
    h.options.write_buffer_bytes);
  CHECK_FALSE(h.index->next_requested());
  CHECK(check_seqnos({1}, h.index->get_write_txs_in_range("key0000", 0, 1)));
  h.settle();
  REQUIRE(h.index->get_indexed_watermark().seqno == 1);
  for (const auto& key : keys)
  {
    CHECK(check_seqnos({1}, h.query(key, 0, 1)));
  }
}

TEST_CASE(
  "Sorted queries progress during unrelated merges" *
  doctest::test_suite("lfs"))
{
  Harness h;
  for (size_t i = 0; i < 128; ++i)
  {
    h.append({"hot"});
  }
  auto result = h.index->get_write_txs_in_range("hot", 1, 8);
  REQUIRE_FALSE(result);
  const auto initial_merges = h.index->describe()["compactions"].get<size_t>();
  for (size_t attempts = 0; !result; ++attempts)
  {
    REQUIRE(attempts < 60);
    // Complete several new flushes/merges between every client retry.
    for (size_t i = 0; i < 12; ++i)
    {
      h.append({"unrelated"});
    }
    result = h.index->get_write_txs_in_range("hot", 1, 8);
  }
  CHECK(result->size() == 8);
  CHECK(h.index->describe()["compactions"].get<size_t>() > initial_merges);
}

TEST_CASE(
  "Sorted exactly-capacity queries succeed" * doctest::test_suite("lfs"))
{
  Harness h(Options{512, 128, 32768, 3});
  for (size_t i = 0; i < 32; ++i)
  {
    h.append({"hot"});
  }
  CHECK(h.query("hot", 1, 32).size() == 32);
  const auto required = h.index->describe()["cached_blocks"].get<size_t>();
  const auto block_charge =
    h.index->describe()["cache_block_bytes"].get<size_t>();
  REQUIRE(required > 1);
  // Recreate exactly the same data/merge layout with precisely this budget.
  h.index.reset();
  h.options.query_cache_bytes = required * block_charge;
  h.index = std::make_shared<Sorted>(map_a, h.context, h.options);
  h.seqno = 0;
  for (size_t i = 0; i < 32; ++i)
  {
    h.append({"hot"});
  }
  CHECK(h.query("hot", 1, 32).size() == 32);
  CHECK(h.index->describe()["cached_blocks"] == required);
  CHECK(h.query("absent", 1, 32).empty());
}

TEST_CASE(
  "Sorted one-block cache reports its exact working-set limit" *
  doctest::test_suite("lfs"))
{
  Harness h(Options{512, 128, 1024, 3});
  for (size_t i = 0; i < 32; ++i)
  {
    h.append({"hot"});
  }
  CHECK_THROWS_WITH_AS(
    h.query("hot", 1, 32),
    "Sorted index query exceeds its 1024-byte block cache. "
    "Request a smaller seqno range or increase query_cache_bytes.",
    std::length_error);
  CHECK(h.index->describe()["cache_capacity_blocks"] == 1);
  CHECK(h.index->describe()["cache_reserved_bytes"].get<size_t>() <= 1024);
  CHECK(h.query("absent", 0, 0).empty());
  CHECK(h.index->get_indexed_watermark().seqno == 32);
}

TEST_CASE("Sorted oversized keys stall explicitly" * doctest::test_suite("lfs"))
{
  Harness h;
  h.submit({std::string(256, 'k')});
  h.step();
  CHECK(h.index->describe()["oversized_key"] == true);
  CHECK(h.index->get_indexed_watermark().seqno == 0);
  CHECK_FALSE(h.index->next_requested());
  CHECK_FALSE(h.index->get_write_txs_in_range("absent", 0, 1));
  CHECK(h.disk_bytes() == 0);
}

TEST_CASE(
  "Sorted query retries follow compaction and concurrent updates" *
  doctest::test_suite("lfs"))
{
  Harness h;
  for (size_t i = 0; i < 40; ++i)
  {
    h.append({"hot", fmt::format("key{}", i)});
  }
  CHECK_FALSE(h.index->get_write_txs_in_range("hot", 1, 40));
  for (size_t i = 0; i < 40; ++i)
  {
    auto query = std::async(std::launch::async, [&]() {
      return h.index->get_write_txs_in_range("hot", 1, 40);
    });
    h.append({"hot", fmt::format("new{}", i)});
    const auto result = query.get();
    if (result)
    {
      CHECK(result->size() == 40);
    }
  }
  CHECK(h.query("hot", 1, 40).size() == 40);
  CHECK(h.query("hot", 1, 80).size() == 80);
  CHECK(h.index->describe()["retired_runs"] == 0);
}

TEST_CASE(
  "Sorted required file failures never return partial or empty success" *
  doctest::test_suite("lfs"))
{
  Harness h;
  for (size_t i = 0; i < 32; ++i)
  {
    h.append({"hot", fmt::format("key{}", i)});
  }
  int failure = 0;
  SUBCASE("Missing")
  {
    failure = 0;
  }
  SUBCASE("Zeroed")
  {
    failure = 1;
  }
  SUBCASE("Truncated")
  {
    failure = 2;
  }
  for (const auto& file : std::filesystem::directory_iterator(".index"))
  {
    if (failure == 0)
    {
      std::filesystem::remove(file.path());
    }
    else
    {
      write_file(
        file.path(),
        std::vector<uint8_t>(failure == 1 ? file.file_size() : 0, 0));
    }
  }
  CHECK_FALSE(h.index->get_write_txs_in_range("hot", 1, 32));
  flush_lfs(h.board);
  CHECK_FALSE(h.index->get_write_txs_in_range("hot", 1, 32));
  CHECK_FALSE(h.index->get_write_txs_in_range("zz-absent", 1, 32));
  h.step();
  REQUIRE(h.index->get_indexed_watermark().seqno == 0);
  h.settle();
  CHECK(h.disk_bytes() == 0);
  h.seqno = 0;
  for (size_t i = 0; i < 32; ++i)
  {
    h.append({"hot"});
  }
  CHECK(h.query("hot", 1, 32).size() == 32);
}

TEST_CASE(
  "Sorted stale valid files cannot replace current files" *
  doctest::test_suite("lfs"))
{
  Harness h;
  for (size_t i = 0; i < 12; ++i)
  {
    h.append({"hot", fmt::format("key{}", i)});
  }
  const auto obsolete_path =
    std::filesystem::directory_iterator(".index")->path();
  const auto obsolete = read_file(obsolete_path);
  for (size_t i = 0; i < 64; ++i)
  {
    h.append({"hot", fmt::format("next{}", i)});
  }
  REQUIRE_FALSE(std::filesystem::exists(obsolete_path));
  for (const auto& file : std::filesystem::directory_iterator(".index"))
  {
    write_file(file.path(), obsolete);
  }
  CHECK_FALSE(h.index->get_write_txs_in_range("hot", 1, h.seqno));
  flush_lfs(h.board);
  CHECK_FALSE(h.index->get_write_txs_in_range("hot", 1, h.seqno));
  h.step();
  REQUIRE(h.index->get_indexed_watermark().seqno == 0);
  h.settle();
  CHECK(h.disk_bytes() == 0);
}

TEST_CASE(
  "Sorted failed replacement writes trigger rebuild and reclamation" *
  doctest::test_suite("lfs"))
{
  Harness h;
  for (size_t i = 0; i < 32; ++i)
  {
    h.append({"hot"});
  }
  for (size_t attempts = 0; h.storage->failed_write.empty(); ++attempts)
  {
    REQUIRE(attempts < 64);
    h.submit({"hot"});
    while (h.index->describe()["busy"].get<bool>())
    {
      if (h.index->describe()["compaction_active"].get<bool>())
      {
        h.storage->fail_next_write = true;
      }
      h.step();
      if (!h.storage->failed_write.empty())
      {
        break;
      }
    }
  }
  // Only one queued output write fails; returning the remaining source or
  // output files alone would be a partial result.
  h.storage->fail_next_write = false;
  h.settle();
  for (size_t attempts = 0; h.index->get_indexed_watermark().seqno != 0;
       ++attempts)
  {
    REQUIRE(attempts < 1000);
    CHECK_FALSE(h.index->get_write_txs_in_range("hot", 1, h.seqno));
    flush_lfs(h.board);
    CHECK_FALSE(h.index->get_write_txs_in_range("hot", 1, h.seqno));
    h.step();
  }
  h.settle();
  CHECK_FALSE(h.index->get_write_txs_in_range("absent", 1, h.seqno));
  CHECK(h.disk_bytes() == 0);
}

TEST_CASE(
  "Sorted ingestion publishes complete transactions without waiting for ticks" *
  doctest::test_suite("lfs"))
{
  Harness h(Options{8192, 128, 32768, 8});
  auto store = std::make_shared<ccf::kv::Store>();
  store->set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  auto tx = store->create_tx();
  tx.wo(map_a)->put("hot", "value");
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  for (size_t seqno = 1; seqno <= 5; ++seqno)
  {
    REQUIRE(h.index->next_requested());
    h.index->handle_committed_transaction({1, seqno}, store);
    CHECK(h.index->get_indexed_watermark().seqno == seqno);
  }
  auto empty_store = std::make_shared<ccf::kv::Store>();
  h.index->handle_committed_transaction({1, 6}, empty_store);
  CHECK(h.index->get_indexed_watermark().seqno == 6);
}

TEST_CASE("Sorted lazy index integration" * doctest::test_suite("lfs"))
{
  ccf::tasks::JobBoard board;
  ccf::AbstractNodeContext context;
  auto storage = std::make_shared<ObservedStorage>(board);
  context.install_subsystem(storage);
  auto strategy = std::make_shared<ccf::indexing::LazyStrategy<Sorted>>(
    map_a, context, Options{512, 128, 32768, 8});
  auto fetcher = std::make_shared<TestTransactionFetcher>();
  ccf::indexing::Indexer indexer(fetcher);
  REQUIRE(indexer.install_strategy(strategy));
  ccf::kv::Store store;
  store.set_encryptor(fetcher->encryptor);
  auto consensus = std::make_shared<AllCommittableConsensus>();
  store.set_consensus(consensus);
  ExpectedSeqNos expected;
  REQUIRE(create_transactions(
    store,
    {{expected,
      [](size_t, ccf::kv::Tx& tx) {
        tx.wo(map_a)->put("hot", "value");
        return true;
      }}},
    40));
  CHECK_FALSE(strategy->next_requested());
  strategy->extend_index_to(store.current_txid());
  for (size_t ticks = 0;
       strategy->get_indexed_watermark() != store.current_txid();
       ++ticks)
  {
    REQUIRE(ticks < 20000);
    indexer.update_strategies(step_time, store.current_txid());
    for (auto seqno : fetcher->requested)
    {
      const auto& entry = std::get<1>(consensus->replica[seqno - 1]);
      fetcher->fetched_stores[seqno] =
        fetcher->deserialise_transaction(seqno, entry->data(), entry->size());
    }
    fetcher->requested.clear();
    flush_lfs(board);
  }
  auto result = strategy->get_write_txs_in_range("hot", 1, 40);
  for (size_t attempts = 0; !result; ++attempts)
  {
    REQUIRE(attempts < 1000);
    flush_lfs(board);
    result = strategy->get_write_txs_in_range("hot", 1, 40);
  }
  CHECK(check_seqnos(expected, result));
  ccf::kv::Value<std::string> value("public:singleton");
  ccf::indexing::strategies::SeqnosForValue_Sorted<decltype(value)> singleton(
    value, context);
  CHECK(singleton.get_write_txs_in_range(0, 0)->empty());
  CHECK_THROWS(Sorted("private:table", context));
}
