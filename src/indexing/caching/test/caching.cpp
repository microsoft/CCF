// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "indexing/caching/enclave_cache.h"
#include "indexing/caching/host_cache.h"

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

  using namespace indexing::caching;

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
    auto result_a = std::make_shared<FetchResult>();
    auto result_b = std::make_shared<FetchResult>();

    REQUIRE(result_a->fetch_result == FetchResult::Fetching);
    REQUIRE(result_b->fetch_result == FetchResult::Fetching);

    ec.fetch(key_a, result_a);
    REQUIRE(result_a->fetch_result == FetchResult::Fetching);

    ec.fetch(key_b, result_b);
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
      hc.root_dir / key_b,
      hc.root_dir / key_a,
      std::filesystem::copy_options::overwrite_existing));

    auto result = std::make_shared<FetchResult>();
    ec.fetch(key_a, result);

    host_bp.read_all(outbound_reader);
    enclave_bp.read_all(inbound_reader);

    REQUIRE(result->fetch_result == FetchResult::Corrupt);
    REQUIRE(result->contents != blob_a);
  }

  {
    INFO("Host cache provides corrupt file");
    const auto b_path = hc.root_dir / key_b;
    const auto original_b_contents = read_file(b_path);

    for (auto i = 0; i < original_b_contents.size(); ++i)
    {
      write_file_corrupted_at(b_path, i, original_b_contents);

      auto result = std::make_shared<FetchResult>();
      ec.fetch(key_b, result);

      host_bp.read_all(outbound_reader);
      enclave_bp.read_all(inbound_reader);

      REQUIRE(result->fetch_result == FetchResult::Corrupt);
      REQUIRE(result->contents != blob_b);
    }
  }
}
