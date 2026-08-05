// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/sha256.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/hex.h"
#include "ccf/pal/locking.h"
#include "ds/files.h"
#include "ds/internal_logger.h"
#include "ds/serialized.h"
#include "host/time_bound_logger.h"
#include "indexing/lfs_interface.h"
#include "tasks/ordered_tasks.h"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <optional>
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

    // Directory where encrypted blobs are persisted to disk
    const std::filesystem::path root_dir = ".index";

    // All disk I/O is performed as actions on this single ordered task queue,
    // off the calling (indexing) thread. A single ordered queue preserves the
    // submission order of stores and fetches, so a fetch issued after a store
    // for the same key always observes the written file.
    std::shared_ptr<ccf::tasks::OrderedTasks> tasks;

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

    void write_blob(
      const LFSKey& obfuscated, const LFSEncryptedContents& encrypted)
    {
      const auto target_path = root_dir / obfuscated;
      asynchost::TimeBoundLogger log_if_slow(fmt::format(
        "Writing LFS file ({} bytes) - {}",
        encrypted.size(),
        target_path.string()));
      LOG_TRACE_FMT(
        "Writing {} byte file to {}", encrypted.size(), target_path.string());
      files::dump(encrypted, target_path);
    }

    std::optional<LFSEncryptedContents> read_blob(const LFSKey& obfuscated)
    {
      const auto target_path = root_dir / obfuscated;
      if (!std::filesystem::is_regular_file(target_path))
      {
        LOG_TRACE_FMT("File {} not found", target_path.string());
        return std::nullopt;
      }

      asynchost::TimeBoundLogger log_if_slow(
        fmt::format("Reading LFS file - ifstream({})", target_path.string()));
      std::ifstream f(target_path, std::ios::binary);
      f.seekg(0, std::ios::end);
      const auto file_size = f.tellg();
      f.seekg(0, std::ios::beg);
      LFSEncryptedContents blob(static_cast<size_t>(file_size));
      f.read(
        reinterpret_cast<char*>(blob.data()),
        static_cast<std::streamsize>(blob.size()));
      return blob;
    }

  public:
    EnclaveLFSAccess(ccf::tasks::JobBoard& job_board) :
      tasks(ccf::tasks::OrderedTasks::create(job_board, "LFSAccess")),
      entropy_src(ccf::crypto::get_entropy())
    {
      // Generate a fresh random key. Only this specific instance can read
      // these files!
      encryption_key = ccf::crypto::make_key_aes_gcm(
        entropy_src->random(ccf::crypto::GCM_DEFAULT_KEY_SIZE));

      if (std::filesystem::is_directory(root_dir))
      {
        LOG_INFO_FMT(
          "Clearing contents from existing directory {}", root_dir.string());
        asynchost::TimeBoundLogger log_if_slow(fmt::format(
          "Clearing LFS index directory - remove_all({})", root_dir.string()));
        std::filesystem::remove_all(root_dir);
      }

      {
        asynchost::TimeBoundLogger log_if_slow(fmt::format(
          "Creating LFS index directory - create_directory({})",
          root_dir.string()));
        if (!std::filesystem::create_directory(root_dir))
        {
          throw std::logic_error(
            fmt::format("Could not create directory: {}", root_dir.string()));
        }
      }
    }

    ~EnclaveLFSAccess() override
    {
      // Stop processing any further queued I/O actions. In production the task
      // threads have already been stopped by this point; in tests actions are
      // drained synchronously before destruction.
      tasks->cancel_task();
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
      // To avoid leaking potentially confidential information, all cached data
      // is encrypted and stored at an obfuscated key. Encryption happens on the
      // calling thread; the resulting blob is written to disk asynchronously.
      auto encrypted = encrypt(obfuscated, std::move(contents));
      tasks->add_action(ccf::tasks::make_basic_action(
        [this, obfuscated, encrypted = std::move(encrypted)]() {
          write_blob(obfuscated, encrypted);
        }));
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

      // Read and decrypt the file from disk asynchronously, updating the
      // result's state when complete.
      tasks->add_action(
        ccf::tasks::make_basic_action([this, obfuscated, result]() {
          auto encrypted = read_blob(obfuscated);
          if (!encrypted.has_value())
          {
            LOG_TRACE_FMT(
              "No contents for key {} (aka {})", obfuscated, result->key);
            result->fetch_result = FetchResult::FetchResultType::NotFound;
          }
          else
          {
            const auto success = verify_and_decrypt(
              *encryption_key,
              obfuscated,
              std::move(*encrypted),
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

          // Drop the pending entry, unless a newer fetch has already replaced
          // it with a different result.
          std::lock_guard<ccf::pal::Mutex> guard(pending_access);
          auto it = pending.find(obfuscated);
          if (it != pending.end() && it->second.lock() == result)
          {
            pending.erase(it);
          }
        }));

      return result;
    }
  };
}