// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "indexing/blob_cache.h"

#include <doctest/doctest.h>

TEST_CASE("Foo" * doctest::test_suite("blobcache"))
{
  messaging::BufferProcessor host_bp("blobcache_host");
  messaging::BufferProcessor enclave_bp("blobcache_enclave");

  std::unordered_map<BlobKey, EncryptedBlob> host_cache;

  constexpr size_t buf_size = 1 << 10;
  auto inbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader inbound_reader(inbound_buffer->bd);
  auto outbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader outbound_reader(outbound_buffer->bd);

  BlobCache bc(
    enclave_bp.get_dispatcher(),
    std::make_shared<ringbuffer::Writer>(outbound_reader));

  DISPATCHER_SET_MESSAGE_HANDLER(
    host_bp, CacheMessage::store_blob, [&](const uint8_t* data, size_t size) {
      auto [key, encrypted_blob] =
        ringbuffer::read_message<CacheMessage::store_blob>(data, size);
      LOG_INFO_FMT(
        "Storing {} byte blob named '{}'", encrypted_blob.size(), key);
      host_cache[key] = encrypted_blob;
    });

  DISPATCHER_SET_MESSAGE_HANDLER(
    host_bp, CacheMessage::get_blob, [&](const uint8_t* data, size_t size) {
      auto [key] = ringbuffer::read_message<CacheMessage::get_blob>(data, size);
      LOG_INFO_FMT("Fetching blob named '{}'", key);
      auto response_writer =
        std::make_shared<ringbuffer::Writer>(inbound_reader);
      const auto it = host_cache.find(key);
      if (it == host_cache.end())
      {
        RINGBUFFER_WRITE_MESSAGE(CacheMessage::no_blob, response_writer, key);
      }
      else
      {
        RINGBUFFER_WRITE_MESSAGE(
          CacheMessage::response_blob, response_writer, key, it->second);
      }
    });

  BlobKey key_a("Blob A");
  BlobContents blob_a{0, 1, 2, 3, 4, 5};

  BlobKey key_b("Blob B");
  BlobContents blob_b{'a', 'b', 'c', 'd', 'e'};

  bc.store(key_a, BlobContents(blob_a));
  bc.store(key_b, BlobContents(blob_b));

  REQUIRE(2 == host_bp.read_n(2, outbound_reader));

  REQUIRE_FALSE(bc.load(key_a).has_value());

  REQUIRE(1 == host_bp.read_n(1, outbound_reader));
  REQUIRE(1 == enclave_bp.read_n(1, inbound_reader));

  REQUIRE(bc.load(key_a).has_value());
}
