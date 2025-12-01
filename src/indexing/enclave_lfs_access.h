// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/sha256.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/hex.h"
#include "ccf/pal/locking.h"
#include "ds/messaging.h"
#include "indexing/lfs_interface.h"
#include "indexing/lfs_ringbuffer_types.h"

#include <optional>
#include <set>
#include <unordered_map>

// Uncomment to disable encryption and obfuscation, writing cache content
// directly unencrypted to host disk
// #define PLAINTEXT_CACHE

#if defined(PLAINTEXT_CACHE)
#  pragma message( \
    "PLAINTEXT_CACHE should only be used for debugging, and not enabled for enclave builds")
#endif

namespace ccf::indexing
{
  static inline bool verify_and_decrypt(
    ccf::crypto::KeyAesGcm& encryption_key,
    const LFSKey& key,
    LFSEncryptedContents&& encrypted,
    std::vector<uint8_t>& plaintext)
  {
    ccf::crypto::GcmCipher gcm;
    gcm.deserialise(encrypted);

#ifdef PLAINTEXT_CACHE
    plaintext = gcm.cipher;
    auto success = true;
#else
    auto success = encryption_key.decrypt(
      gcm.hdr.get_iv(), gcm.hdr.tag, gcm.cipher, {}, plaintext);
#endif

    // Check key prefix in plaintext
    {
      const auto encoded_prefix_size = sizeof(key.size()) + key.size();
      if (plaintext.size() < encoded_prefix_size)
      {
        return false;
      }

      const auto* data = reinterpret_cast<const uint8_t*>(plaintext.data());
      auto size = plaintext.size();
      const auto prefix_size = serialized::read<size_t>(data, size);
      if (prefix_size != key.size())
      {
        success = false;
      }
      else
      {
        if (memcmp(data, key.data(), key.size()) != 0)
        {
          success = false;
        }

        plaintext.erase(
          plaintext.begin(), plaintext.begin() + encoded_prefix_size);
      }
    }

    if (success)
    {
      return true;
    }

    LOG_TRACE_FMT("Decryption failed for {}", key);
    return false;
  }

  class EnclaveLFSAccess : public AbstractLFSAccess
  {
  protected:
    using PendingResult = std::weak_ptr<FetchResult>;

    std::unordered_map<LFSKey, PendingResult> pending;
    ccf::pal::Mutex pending_access;

    ringbuffer::WriterPtr to_host;

    ccf::crypto::EntropyPtr entropy_src;
    std::unique_ptr<ccf::crypto::KeyAesGcm> encryption_key;

    LFSEncryptedContents encrypt(const LFSKey& key, LFSContents&& contents)
    {
      // Prefix the contents with the key, to be checked during decryption
      {
        std::vector<uint8_t> key_prefix(sizeof(key.size()) + key.size());
        auto* data = key_prefix.data();
        auto size = key_prefix.size();
        serialized::write(data, size, key);
        contents.insert(contents.begin(), key_prefix.begin(), key_prefix.end());
      }

      ccf::crypto::GcmCipher gcm(contents.size());

      // Use a random IV for each call
      gcm.hdr.set_random_iv();

      encryption_key->encrypt(
        gcm.hdr.get_iv(), contents, {}, gcm.cipher, gcm.hdr.tag);

#ifdef PLAINTEXT_CACHE
      gcm.cipher = contents;
#endif

      return gcm.serialise();
    }

  public:
    EnclaveLFSAccess(ringbuffer::WriterPtr writer) :
      to_host(std::move(writer)),
      entropy_src(ccf::crypto::get_entropy())
    {
      // Generate a fresh random key. Only this specific instance, in this
      // enclave, can read these files!
      encryption_key = ccf::crypto::make_key_aes_gcm(
        entropy_src->random(ccf::crypto::GCM_DEFAULT_KEY_SIZE));
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& dispatcher)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        dispatcher, LFSMsg::response, [this](const uint8_t* data, size_t size) {
          auto [obfuscated, encrypted] =
            ringbuffer::read_message<LFSMsg::response>(data, size);
          std::lock_guard<ccf::pal::Mutex> guard(pending_access);
          auto it = pending.find(obfuscated);
          if (it != pending.end())
          {
            auto result = it->second.lock();
            if (result != nullptr)
            {
              if (
                result->fetch_result == FetchResult::FetchResultType::Fetching)
              {
                const auto success = verify_and_decrypt(
                  *encryption_key,
                  obfuscated,
                  std::move(encrypted),
                  result->contents);
                if (success)
                {
                  result->fetch_result = FetchResult::FetchResultType::Loaded;
                }
                else
                {
                  result->fetch_result = FetchResult::FetchResultType::Corrupt;
                  LOG_TRACE_FMT(
                    "Cache was given invalid contents for {} (aka {})",
                    obfuscated,
                    result->key);
                }
              }
              else
              {
                LOG_FAIL_FMT(
                  "Retained result for {} (aka {}) in state {}",
                  obfuscated,
                  result->key,
                  result->fetch_result);
              }
            }
            else
            {
              LOG_TRACE_FMT(
                "Received response for {}, but caller has already dropped "
                "result",
                obfuscated);
            }
            pending.erase(it);
          }
          else
          {
            LOG_TRACE_FMT(
              "Ignoring response message for unrequested key {}", obfuscated);
          }
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        dispatcher,
        LFSMsg::not_found,
        [this](const uint8_t* data, size_t size) {
          auto [obfuscated] =
            ringbuffer::read_message<LFSMsg::not_found>(data, size);
          std::lock_guard<ccf::pal::Mutex> guard(pending_access);
          auto it = pending.find(obfuscated);
          if (it != pending.end())
          {
            auto result = it->second.lock();
            if (result != nullptr)
            {
              if (
                result->fetch_result == FetchResult::FetchResultType::Fetching)
              {
                LOG_TRACE_FMT(
                  "Host has no contents for key {} (aka {})",
                  obfuscated,
                  result->key);
                result->fetch_result = FetchResult::FetchResultType::NotFound;
              }
              else
              {
                LOG_FAIL_FMT(
                  "Retained result for {} (aka {}) in state {}",
                  obfuscated,
                  result->key,
                  result->fetch_result);
              }
            }
            else
            {
              LOG_TRACE_FMT(
                "Received not_found for {}, but caller has already dropped "
                "result",
                obfuscated);
            }
            pending.erase(it);
          }
          else
          {
            LOG_TRACE_FMT(
              "Ignoring not_found message for unrequested key {}", obfuscated);
          }
        });
    }

    static LFSKey obfuscate_key(const LFSKey& key)
    {
#ifdef PLAINTEXT_CACHE
      return key;
#else
      const auto h = ccf::crypto::sha256(
        reinterpret_cast<const uint8_t*>(key.data()), key.size());
      return ds::to_hex(h);
#endif
    }

    void store(const LFSKey& key, LFSContents&& contents) override
    {
      const auto obfuscated = obfuscate_key(key);
      RINGBUFFER_WRITE_MESSAGE(
        LFSMsg::store,
        to_host,
        // To avoid leaking potentially confidential information to the host,
        // all cached data is encrypted and stored at an obfuscated key
        obfuscated,
        encrypt(obfuscated, std::move(contents)));
    }

    FetchResultPtr fetch(const LFSKey& key) override
    {
      const auto obfuscated = obfuscate_key(key);
      std::lock_guard<ccf::pal::Mutex> guard(pending_access);
      auto it = pending.find(obfuscated);

      FetchResultPtr result;

      if (it != pending.end())
      {
        result = it->second.lock();
        if (result != nullptr)
        {
          if (key != result->key)
          {
            throw std::runtime_error(fmt::format(
              "Obfuscation collision for unique keys '{}' and '{}', both "
              "obfuscated to '{}'",
              key,
              result->key,
              obfuscated));
          }

          return result;
        }

        result = std::make_shared<FetchResult>();
        it->second = result;
      }
      else
      {
        result = std::make_shared<FetchResult>();
        pending.emplace(obfuscated, result);
      }

      result->fetch_result = FetchResult::FetchResultType::Fetching;
      result->key = key;
      RINGBUFFER_WRITE_MESSAGE(LFSMsg::get, to_host, obfuscated);
      return result;
    }
  };
}