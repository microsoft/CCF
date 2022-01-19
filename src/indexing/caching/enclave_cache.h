// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "message_types.h"
#include "crypto/entropy.h"
#include "crypto/hash.h"
#include "crypto/symmetric_key.h"
#include "ds/messaging.h"

#include <optional>
#include <set>
#include <unordered_map>

namespace indexing::caching
{
  using BlobContents = std::vector<uint8_t>;

  struct FetchResult
  {
    enum
    {
      Fetching,
      Loaded,
      NotFound,
      Corrupt,
    } fetch_result;

    std::vector<uint8_t> contents;
  };

  using FetchResultPtr = std::shared_ptr<FetchResult>;

  class EnclaveCache
  {
  protected:
    using PendingResult = std::weak_ptr<FetchResult>;

    std::unordered_map<BlobKey, PendingResult> pending;

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

    bool verify_and_decrypt(
      const BlobKey& key,
      EncryptedBlob&& encrypted,
      std::vector<uint8_t>& plaintext)
    {
      crypto::GcmCipher gcm;
      gcm.deserialise(encrypted);

      const CBuffer given_iv = gcm.hdr.get_iv();
      const auto expected_iv = get_iv(key);
      if (
        given_iv.n != expected_iv.size() ||
        (memcmp(given_iv.p, expected_iv.data(), given_iv.n) != 0))
      {
        LOG_TRACE_FMT(
          "IV mismatch for {}: {:02x} != {:02x}",
          key,
          fmt::join(given_iv.p, given_iv.p + given_iv.n, " "),
          fmt::join(get_iv(key), " "));
        return false;
      }

      plaintext.resize(gcm.cipher.size());
      const auto success = encryption_key->decrypt(
        gcm.hdr.get_iv(), gcm.hdr.tag, gcm.cipher, nullb, plaintext.data());

      if (success)
      {
        return true;
      }
      else
      {
        LOG_TRACE_FMT("Decryption failed for {}", key);
        return false;
      }
    }

  public:
    EnclaveCache(
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
        BlobMsg::response,
        [this](const uint8_t* data, size_t size) {
          auto [key, encrypted_blob] =
            ringbuffer::read_message<BlobMsg::response>(data, size);
          auto it = pending.find(key);
          if (it != pending.end())
          {
            auto result = it->second.lock();
            if (result != nullptr)
            {
              if (result->fetch_result == FetchResult::Fetching)
              {
                const auto success = verify_and_decrypt(
                  key, std::move(encrypted_blob), result->contents);
                if (success)
                {
                  result->fetch_result = FetchResult::Loaded;
                }
                else
                {
                  result->fetch_result = FetchResult::Corrupt;
                  LOG_TRACE_FMT("Cache was given invalid blob for {}", key);
                }
              }
              else
              {
                LOG_FAIL_FMT(
                  "Retained result for {} in state {}",
                  key,
                  result->fetch_result);
              }
            }
            else
            {
              LOG_TRACE_FMT(
                "Received response for {}, but caller has already dropped "
                "result");
            }
            pending.erase(it);
          }
          else
          {
            LOG_TRACE_FMT(
              "Ignoring response message for unrequested key {}", key);
          }
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        dispatcher,
        BlobMsg::not_found,
        [this](const uint8_t* data, size_t size) {
          auto [key] = ringbuffer::read_message<BlobMsg::not_found>(data, size);
          auto it = pending.find(key);
          if (it != pending.end())
          {
            auto result = it->second.lock();
            if (result != nullptr)
            {
              if (result->fetch_result == FetchResult::Fetching)
              {
                result->fetch_result = FetchResult::NotFound;
              }
              else
              {
                LOG_FAIL_FMT(
                  "Retained result for {} in state {}",
                  key,
                  result->fetch_result);
              }
            }
            else
            {
              LOG_TRACE_FMT(
                "Received not_found for {}, but caller has already dropped "
                "result");
            }
            LOG_TRACE_FMT("Host has no blob for key {}", key);
            pending.erase(it);
          }
          else
          {
            LOG_TRACE_FMT(
              "Ignoring not_found message for unrequested key {}", key);
          }
        });
    }

    void store(const BlobKey& key, BlobContents&& contents)
    {
      RINGBUFFER_WRITE_MESSAGE(
        BlobMsg::store, to_host, key, encrypt(key, std::move(contents)));
    }

    void fetch(const BlobKey& key, const FetchResultPtr& result)
    {
      auto it = pending.find(key);
      if (it == pending.end())
      {
        result->fetch_result = FetchResult::Fetching;
        pending.emplace(key, result);
        RINGBUFFER_WRITE_MESSAGE(BlobMsg::get, to_host, key);
      }
    }
  };
}