// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/spin_lock.h"
#include "kv/kv_types.h"
#include "tls/entropy.h"

#include <algorithm>
#include <map>

namespace ccf
{
  class NewLedgerSecrets
  {
  public:
    struct NewLedgerSecret
    {
      crypto::KeyAesGcm key;

      // Keep track of raw key to passed on to new nodes on join
      std::vector<uint8_t> raw_key;

      NewLedgerSecret(std::vector<uint8_t>&& raw_key_) :
        key(raw_key_),
        raw_key(std::move(raw_key_))
      {}
    };

  private:
    SpinLock lock;
    using EncryptionKeys =
      std::map<kv::Version, std::shared_ptr<NewLedgerSecret>>;
    EncryptionKeys encryption_keys;
    EncryptionKeys::iterator commit_key_it = encryption_keys.end();

  public:
    NewLedgerSecrets()
    {
      encryption_keys.emplace(
        1,
        std::make_shared<NewLedgerSecret>(
          tls::create_entropy()->random(crypto::GCM_SIZE_KEY)));
      commit_key_it = encryption_keys.begin();
    }

    EncryptionKeys::iterator get_encryption_key_it(kv::Version version)
    {
      // Encryption keys lock should be taken before calling this function

      // Encryption key for a given version is the one with the highest version
      // that is lower than the given version (e.g. if encryption_keys contains
      // two keys for version 0 and 10 then the key associated with version 0
      // is used for version [0..9] and version 10 for versions 10+)

      auto search = std::upper_bound(
        commit_key_it,
        encryption_keys.end(),
        version,
        [](auto a, const auto& b) {
          LOG_FAIL_FMT("Considering key at seqno {}", b.first);
          return b.first > a;
        });
      if (search == commit_key_it)
      {
        throw std::logic_error(fmt::format(
          "TxEncryptor: could not find ledger encryption key for seqno {}",
          version));
      }
      return --search;
    }

    void update(kv::Version version, std::vector<uint8_t>&& key)
    {
      std::lock_guard<SpinLock> guard(lock);

      CCF_ASSERT_FMT(
        encryption_keys.find(version) == encryption_keys.end(),
        "Encryption key at {} already exists",
        version);

      encryption_keys.emplace(
        version, std::make_shared<NewLedgerSecret>(std::move(key)));

      LOG_TRACE_FMT("Added new encryption key at seqno {}", version);
    }

    void rollback(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);

      if (version < commit_key_it->first)
      {
        LOG_FAIL_FMT(
          "Cannot rollback encryptor at {}: committed key is at {}",
          version,
          commit_key_it->first);
        return;
      }

      while (std::distance(commit_key_it, encryption_keys.end()) > 1)
      {
        auto k = encryption_keys.rbegin();
        if (k->first <= version)
        {
          break;
        }

        LOG_TRACE_FMT("Rollback encryption key at seqno {}", k->first);
        encryption_keys.erase(k->first);
      }
    }

    void compact(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);

      commit_key_it = get_encryption_key_it(version);
      LOG_TRACE_FMT(
        "First usable encryption key is now at seqno {}", commit_key_it->first);
    }
  };
}