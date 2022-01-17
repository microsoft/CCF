// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "indexing/blob_cache.h"

#include <doctest/doctest.h>
#include <filesystem>
struct HostCache
{
  const std::filesystem::path root_dir = ".cache";

  ringbuffer::WriterPtr writer;

  HostCache(messaging::RingbufferDispatcher& disp, ringbuffer::WriterPtr&& w) :
    writer(w)
  {
    if (std::filesystem::is_directory(root_dir))
    {
      LOG_INFO_FMT("Clearing cache from existing directory {}", root_dir);
      std::filesystem::remove_all(root_dir);
    }

    if (!std::filesystem::create_directory(root_dir))
    {
      throw std::logic_error(
        fmt::format("Could not create cache directory: {}", root_dir));
    }

    DISPATCHER_SET_MESSAGE_HANDLER(
      disp, CacheMessage::store_blob, [&](const uint8_t* data, size_t size) {
        auto [key, encrypted_blob] =
          ringbuffer::read_message<CacheMessage::store_blob>(data, size);

        const auto blob_path = root_dir / key;
        std::ofstream f(blob_path, std::ios::trunc | std::ios::binary);
        f.write((char const*)encrypted_blob.data(), encrypted_blob.size());
        f.close();
      });

    DISPATCHER_SET_MESSAGE_HANDLER(
      disp, CacheMessage::get_blob, [&](const uint8_t* data, size_t size) {
        auto [key] =
          ringbuffer::read_message<CacheMessage::get_blob>(data, size);

        const auto blob_path = root_dir / key;
        if (std::filesystem::is_regular_file(blob_path))
        {
          std::ifstream f(blob_path, std::ios::binary);
          f.seekg(0, f.end);
          const auto size = f.tellg();
          f.seekg(0, f.beg);

          EncryptedBlob blob(size);
          f.read((char*)blob.data(), blob.size());
          f.close();
          RINGBUFFER_WRITE_MESSAGE(
            CacheMessage::response_blob, writer, key, blob);
        }
        else
        {
          RINGBUFFER_WRITE_MESSAGE(CacheMessage::no_blob, writer, key);
        }
      });
  }
};

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

  HostCache hc(
    host_bp.get_dispatcher(),
    std::make_shared<ringbuffer::Writer>(inbound_reader));

  BlobCache bc(
    enclave_bp.get_dispatcher(),
    std::make_shared<ringbuffer::Writer>(outbound_reader));

  BlobKey key_a("Blob A");
  BlobContents blob_a{0, 1, 2, 3, 4, 5, 6, 7};

  BlobKey key_b("Blob B");
  BlobContents blob_b{'a', 'b', 'c'};

  bc.store(key_a, BlobContents(blob_a));
  bc.store(key_b, BlobContents(blob_b));

  REQUIRE(2 == host_bp.read_all(outbound_reader));

  {
    INFO("Load one entry");
    REQUIRE_FALSE(bc.load(key_a).has_value());

    REQUIRE(1 == host_bp.read_all(outbound_reader));
    REQUIRE(1 == enclave_bp.read_all(inbound_reader));

    const auto loaded_a = bc.load(key_a);
    REQUIRE(loaded_a.has_value());
    REQUIRE(*loaded_a == blob_a);

    // Can it be requested multiple times, or has it been aggressively deleted?
    REQUIRE(bc.load(key_a).has_value());
  }

  {
    INFO("Load another entry");
    REQUIRE_FALSE(bc.load(key_b).has_value());

    REQUIRE(1 == host_bp.read_all(outbound_reader));
    REQUIRE(1 == enclave_bp.read_all(inbound_reader));

    const auto loaded_b = bc.load(key_b);
    REQUIRE(loaded_b.has_value());
    REQUIRE(*loaded_b == blob_b);
  }

  bc.clear();

  {
    INFO("Host cache provides wrong file");
    REQUIRE(std::filesystem::copy_file(
      hc.root_dir / key_b,
      hc.root_dir / key_a,
      std::filesystem::copy_options::overwrite_existing));

    REQUIRE_FALSE(bc.load(key_a).has_value());

    REQUIRE(1 == host_bp.read_all(outbound_reader));
    REQUIRE(1 == enclave_bp.read_all(inbound_reader));

    REQUIRE_FALSE(bc.load(key_a).has_value());
  }

  {
    INFO("Host cache provides corrupt file");
    const auto b_path = hc.root_dir / key_b;
    const auto original_b_contents = read_file(b_path);

    for (auto i = 0; i < original_b_contents.size(); ++i)
    {
      write_file_corrupted_at(b_path, i, original_b_contents);

      REQUIRE_FALSE(bc.load(key_b).has_value());

      REQUIRE(1 <= host_bp.read_all(outbound_reader));
      REQUIRE(1 <= enclave_bp.read_all(inbound_reader));

      REQUIRE_FALSE(bc.load(key_b).has_value());
    }
  }
}
