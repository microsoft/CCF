// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/hmac.h"
#include "ccf/crypto/sha256.h"
#include "ccf/ds/hex.h"
#include "ds/internal_logger.h"
#include "indexing/lfs_interface.h"
#include "tasks/ordered_tasks.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <openssl/crypto.h>

namespace ccf::indexing
{
  class EnclaveLFSAccess : public AbstractLFSAccess
  {
    static constexpr size_t tag_size = 32;
    const std::filesystem::path root_dir;
    const std::vector<uint8_t> mac_key;
    std::shared_ptr<ccf::tasks::OrderedTasks> tasks;
    std::atomic<size_t> max_payload_bytes = 0;

    ccf::crypto::HashBytes mac(
      const LFSKey& key, const LFSContents& contents) const
    {
      const auto identity = ccf::crypto::sha256(
        reinterpret_cast<const uint8_t*>(key.data()), key.size());
      LFSContents authenticated(identity.begin(), identity.end());
      authenticated.insert(
        authenticated.end(), contents.begin(), contents.end());
      return ccf::crypto::hmac(
        ccf::crypto::MDType::SHA256, mac_key, authenticated);
    }

  public:
    explicit EnclaveLFSAccess(
      ccf::tasks::JobBoard& board, std::filesystem::path directory = ".index") :
      root_dir(std::move(directory)),
      mac_key(ccf::crypto::get_entropy()->random(32)),
      tasks(ccf::tasks::OrderedTasks::create(board, "Index files"))
    {
      std::filesystem::remove_all(root_dir);
      std::filesystem::create_directories(root_dir);
    }

    ~EnclaveLFSAccess() override
    {
      tasks->cancel_task();
    }

    static std::string filename(const LFSKey& key)
    {
      // Bucketed keys may contain path separators or exceed filename limits.
      // Hashing gives safe, fixed-length filenames, not confidentiality;
      // Sorted's generated identities alone would not require it.
      return ds::to_hex(ccf::crypto::sha256(
        reinterpret_cast<const uint8_t*>(key.data()), key.size()));
    }

    void store(const LFSKey& key, LFSContents&& contents) override
    {
      auto current = max_payload_bytes.load();
      while (current < contents.size() &&
             !max_payload_bytes.compare_exchange_weak(current, contents.size()))
      {
      }
      tasks->add_action(ccf::tasks::make_basic_action(
        [this, key, contents = std::move(contents)]() {
          const auto path = root_dir / filename(key);
          const auto tag = mac(key, contents);
          std::ofstream f(path, std::ios::binary | std::ios::trunc);
          f.write(
            reinterpret_cast<const char*>(contents.data()), contents.size());
          f.write(reinterpret_cast<const char*>(tag.data()), tag.size());
          f.close();
          if (!f)
          {
            LOG_FAIL_FMT("Failed to write index file {}", path.string());
          }
        }));
    }

    FetchResultPtr fetch(const LFSKey& key) override
    {
      auto result = std::make_shared<FetchResult>();
      result->key = key;
      tasks->add_action(ccf::tasks::make_basic_action([this, key, result]() {
        using State = FetchResult::FetchResultType;
        auto state = State::Corrupt;
        const auto path = root_dir / filename(key);
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f)
        {
          state = State::NotFound;
        }
        else
        {
          const auto length = f.tellg();
          if (
            length >= static_cast<std::streamoff>(tag_size) &&
            length <=
              static_cast<std::streamoff>(max_payload_bytes.load() + tag_size))
          {
            LFSContents data(static_cast<size_t>(length) - tag_size);
            std::array<uint8_t, tag_size> tag{};
            f.seekg(0);
            f.read(reinterpret_cast<char*>(data.data()), data.size());
            f.read(reinterpret_cast<char*>(tag.data()), tag.size());
            if (
              f &&
              CRYPTO_memcmp(tag.data(), mac(key, data).data(), tag_size) == 0)
            {
              result->contents = std::move(data);
              state = State::Loaded;
            }
          }
        }
        if (state != State::Loaded)
        {
          LOG_FAIL_FMT("Missing or corrupt index file {}", path.string());
        }
        result->fetch_result.store(state);
      }));
      return result;
    }

    void remove(const LFSKey& key) override
    {
      tasks->add_action(ccf::tasks::make_basic_action([this, key]() {
        const auto path = root_dir / filename(key);
        std::error_code ec;
        std::filesystem::remove(path, ec);
        if (ec)
        {
          LOG_FAIL_FMT(
            "Failed to remove index file {}: {}", path.string(), ec.message());
        }
      }));
    }
  };
}
