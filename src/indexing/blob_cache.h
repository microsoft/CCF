// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "blob_cache_types.h"
#include "crypto/entropy.h"
#include "crypto/hash.h"
#include "crypto/symmetric_key.h"
#include "ds/messaging.h"

#include <optional>
#include <set>
#include <unordered_map>

// TODO: Settle on a name, move these files under indexing?
using BlobContents = std::vector<uint8_t>;

class BlobCache
{
protected:
  std::unordered_map<BlobKey, BlobContents> fetched;
  std::set<BlobKey> fetching;

  ringbuffer::WriterPtr to_host;

  crypto::EntropyPtr entropy_src;
  std::unique_ptr<crypto::KeyAesGcm> encryption_key;

  std::vector<uint8_t> get_iv(const BlobKey& key)
  {
    auto h = crypto::SHA256((const uint8_t*)key.data(), key.size());
    h.resize(crypto::GCM_SIZE_IV);
    return h;
  }

  EncryptedBlob encrypt(const BlobKey& key, BlobContents&& contents)
  {
    crypto::GcmCipher gcm(contents.size());
    auto iv = get_iv(key);
    gcm.hdr.set_iv(iv.data(), iv.size());

    encryption_key->encrypt(
      gcm.hdr.get_iv(), contents, nullb, gcm.cipher.data(), gcm.hdr.tag);

    return gcm.serialise();
  }

  std::optional<BlobContents> verify_and_decrypt(
    const BlobKey& key, EncryptedBlob&& encrypted_blob)
  {
    crypto::GcmCipher gcm;
    gcm.deserialise(encrypted_blob);

    const CBuffer given_iv = gcm.hdr.get_iv();
    const auto expected_iv = get_iv(key);
    if (
      given_iv.n != expected_iv.size() ||
      (memcmp(given_iv.p, expected_iv.data(), given_iv.n) != 0))
    {
      LOG_TRACE_FMT(
        "IV mismatch {:02x} != {:02x}",
        fmt::join(given_iv.p, given_iv.p + given_iv.n, " "),
        fmt::join(get_iv(key), " "));
      return std::nullopt;
    }

    std::vector<uint8_t> blob(gcm.cipher.size());

    const auto success = encryption_key->decrypt(
      gcm.hdr.get_iv(), gcm.hdr.tag, gcm.cipher, nullb, blob.data());

    if (success)
    {
      return std::move(blob);
    }
    else
    {
      return std::nullopt;
    }
  }

public:
  BlobCache(
    messaging::Dispatcher<ringbuffer::Message>& dispatcher,
    const ringbuffer::WriterPtr& writer) :
    to_host(writer),
    entropy_src(crypto::create_entropy())
  {
    // Generate a fresh random key. Only this specific instance, in this
    // enclave, can read these blobs!
    encryption_key =
      crypto::make_key_aes_gcm(entropy_src->random(crypto::GCM_SIZE_KEY));

    DISPATCHER_SET_MESSAGE_HANDLER(
      dispatcher,
      CacheMessage::response_blob,
      [this](const uint8_t* data, size_t size) {
        auto [key, encrypted_blob] =
          ringbuffer::read_message<CacheMessage::response_blob>(data, size);
        auto it = fetching.find(key);
        if (it != fetching.end())
        {
          auto decrypted = verify_and_decrypt(key, std::move(encrypted_blob));
          if (decrypted.has_value())
          {
            fetched.emplace(key, decrypted.value());
          }
          else
          {
            LOG_FAIL_FMT("Cache was given invalid blob for {}", key);
          }
          fetching.erase(it);
        }
        else
        {
          LOG_TRACE_FMT(
            "Ignoring response_blob message for unrequested key {}", key);
        }
      });

    DISPATCHER_SET_MESSAGE_HANDLER(
      dispatcher,
      CacheMessage::no_blob,
      [this](const uint8_t* data, size_t size) {
        auto [key] =
          ringbuffer::read_message<CacheMessage::no_blob>(data, size);
        auto it = fetching.find(key);
        if (it != fetching.end())
        {
          // TODO: Record this claim of no blob somewhere
          LOG_INFO_FMT("Host claims to have no blob for key {}", key);
          fetching.erase(it);
        }
        else
        {
          LOG_TRACE_FMT("Ignoring no_blob message for unrequested key {}", key);
        }
      });
  }

  void store(const BlobKey& key, BlobContents&& contents)
  {
    RINGBUFFER_WRITE_MESSAGE(
      CacheMessage::store_blob,
      to_host,
      key,
      encrypt(key, std::move(contents)));
  }

  // TODO: How do we distinguish blobs that are being fetched, from blobs that
  // we've been told don't exist?
  std::optional<BlobContents> load(const BlobKey& key)
  {
    auto it = fetched.find(key);
    if (it != fetched.end())
    {
      return it->second;
    }
    else
    {
      fetching.insert(key);
      RINGBUFFER_WRITE_MESSAGE(CacheMessage::get_blob, to_host, key);
      return std::nullopt;
    }
  }

  // TODO: Maybe only needed for testing? But we need some kind of caching limit
  // on what we store in fetched
  void clear()
  {
    fetched.clear();
  }
};