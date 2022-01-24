// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/lfs_interface.h"
#include "crypto/entropy.h"
#include "crypto/hash.h"
#include "crypto/symmetric_key.h"
#include "ds/hex.h"
#include "ds/messaging.h"

#include <optional>
#include <set>
#include <unordered_map>

// Uncomment to disable encryption and obfuscation, writing cache content
// directly unencrypted to host disk
// #define PLAINTEXT_CACHE

namespace ccf::indexing
{
  static inline std::vector<uint8_t> get_iv(const LFSKey& key)
  {
    auto h = crypto::SHA256((const uint8_t*)key.data(), key.size());
    h.resize(crypto::GCM_SIZE_IV);
    return h;
  }

  static inline LFSEncryptedContents encrypt(
    crypto::KeyAesGcm& encryption_key,
    const LFSKey& key,
    LFSContents&& contents)
  {
    crypto::GcmCipher gcm(contents.size());
    auto iv = get_iv(key);
    gcm.hdr.set_iv(iv.data(), iv.size());

    encryption_key.encrypt(
      gcm.hdr.get_iv(), contents, nullb, gcm.cipher.data(), gcm.hdr.tag);

#ifdef PLAINTEXT_CACHE
    gcm.cipher = contents;
#endif

    return gcm.serialise();
  }

  static inline bool verify_and_decrypt(
    crypto::KeyAesGcm& encryption_key,
    const LFSKey& key,
    LFSEncryptedContents&& encrypted,
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

#ifdef PLAINTEXT_CACHE
    plaintext = gcm.cipher;
    const auto success = true;
#else
    plaintext.resize(gcm.cipher.size());
    const auto success = encryption_key.decrypt(
      gcm.hdr.get_iv(), gcm.hdr.tag, gcm.cipher, nullb, plaintext.data());
#endif

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

  class EnclaveLFSAccess : public AbstractLFSAccess
  {
  protected:
    using PendingResult = std::weak_ptr<FetchResult>;

    std::unordered_map<LFSKey, PendingResult> pending;

    ringbuffer::WriterPtr to_host;

    crypto::EntropyPtr entropy_src;
    std::unique_ptr<crypto::KeyAesGcm> encryption_key;

  public:
    EnclaveLFSAccess(const ringbuffer::WriterPtr& writer) :
      to_host(writer),
      entropy_src(crypto::create_entropy())
    {
      // Generate a fresh random key. Only this specific instance, in this
      // enclave, can read these files!
      encryption_key =
        crypto::make_key_aes_gcm(entropy_src->random(crypto::GCM_SIZE_KEY));
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& dispatcher)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        dispatcher, LFSMsg::response, [this](const uint8_t* data, size_t size) {
          auto [obfuscated, encrypted] =
            ringbuffer::read_message<LFSMsg::response>(data, size);
          auto it = pending.find(obfuscated);
          if (it != pending.end())
          {
            auto result = it->second.lock();
            if (result != nullptr)
            {
              if (result->fetch_result == FetchResult::Fetching)
              {
                const auto success = verify_and_decrypt(
                  *encryption_key,
                  obfuscated,
                  std::move(encrypted),
                  result->contents);
                if (success)
                {
                  result->fetch_result = FetchResult::Loaded;
                }
                else
                {
                  result->fetch_result = FetchResult::Corrupt;
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
          auto it = pending.find(obfuscated);
          if (it != pending.end())
          {
            auto result = it->second.lock();
            if (result != nullptr)
            {
              if (result->fetch_result == FetchResult::Fetching)
              {
                LOG_TRACE_FMT(
                  "Host has no contents for key {} (aka {})",
                  obfuscated,
                  result->key);
                result->fetch_result = FetchResult::NotFound;
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

    static inline LFSKey obfuscate_key(const LFSKey& key)
    {
#ifdef PLAINTEXT_CACHE
      return key;
#else
      const auto h = crypto::SHA256((const uint8_t*)key.data(), key.size());
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
        encrypt(*encryption_key, obfuscated, std::move(contents)));
    }

    FetchResultPtr fetch(const LFSKey& key) override
    {
      const auto obfuscated = obfuscate_key(key);
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
        else
        {
          result = std::make_shared<FetchResult>();
          it->second = result;
        }
      }
      else
      {
        result = std::make_shared<FetchResult>();
        pending.emplace(obfuscated, result);
      }

      result->fetch_result = FetchResult::Fetching;
      result->key = key;
      RINGBUFFER_WRITE_MESSAGE(LFSMsg::get, to_host, obfuscated);
      return result;
    }
  };
}