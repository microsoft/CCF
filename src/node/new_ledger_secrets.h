// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
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
      std::vector<uint8_t> raw_key;

      std::shared_ptr<crypto::KeyAesGcm> key;

      bool operator==(const NewLedgerSecret& other) const
      {
        return raw_key == other.raw_key;
      }

      NewLedgerSecret() = default;

      NewLedgerSecret(const NewLedgerSecret& other) :
        raw_key(other.raw_key),
        key(std::make_shared<crypto::KeyAesGcm>(other.raw_key))
      {}

      NewLedgerSecret(std::vector<uint8_t>&& raw_key_) :
        raw_key(raw_key_),
        key(std::make_shared<crypto::KeyAesGcm>(std::move(raw_key_)))
      {}
    };

    using EncryptionKeys = std::map<kv::Version, NewLedgerSecret>;
    EncryptionKeys encryption_keys;

    NewLedgerSecrets() = default;

    NewLedgerSecrets(const NewLedgerSecrets& other) :
      encryption_keys(other.encryption_keys)
    {
      // commit_key_it = encryption_keys.begin();
    }

    bool operator==(const NewLedgerSecrets& other) const
    {
      return encryption_keys == other.encryption_keys;
    }

    void init()
    {
      encryption_keys.emplace(
        1, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
      // commit_key_it = encryption_keys.begin();
    }

  private:
    // TODO: Encryption keys compaction doesn't work. Ignored for now.
    // EncryptionKeys::iterator commit_key_it = encryption_keys.end();

    EncryptionKeys::iterator get_encryption_key_it(kv::Version version)
    {
      // Encryption key for a given version is the one with the highest version
      // that is lower than the given version (e.g. if encryption_keys contains
      // two keys for version 0 and 10 then the key associated with version 0
      // is used for version [0..9] and version 10 for versions 10+)

      auto search = std::upper_bound(
        encryption_keys.begin(),
        encryption_keys.end(),
        version,
        [](auto a, const auto& b) { return b.first > a; });
      if (search == encryption_keys.begin())
      {
        throw std::logic_error(fmt::format(
          "TxEncryptor: could not find ledger encryption key for seqno {}",
          version));
      }
      return --search;
    }

  public:
    std::shared_ptr<crypto::KeyAesGcm> get_encryption_key_for(
      kv::Version version)
    {
      return get_encryption_key_it(version)->second.key;
    }

    void update_encryption_key(kv::Version version, std::vector<uint8_t>&& key)
    {
      CCF_ASSERT_FMT(
        encryption_keys.find(version) == encryption_keys.end(),
        "Encryption key at {} already exists",
        version);

      encryption_keys.emplace(version, std::move(key));

      LOG_TRACE_FMT("Added new encryption key at seqno {}", version);
    }

    void rollback(kv::Version version)
    {
      if (version < encryption_keys.begin()->first)
      {
        LOG_FAIL_FMT(
          "Cannot rollback encryptor at {}: committed key is at {}",
          version,
          encryption_keys.begin()->first);
        return;
      }

      while (std::distance(encryption_keys.begin(), encryption_keys.end()) > 1)
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
      (void)version;
      // commit_key_it = get_encryption_key_it(version);
      // LOG_TRACE_FMT(
      // "First usable encryption key is now at seqno {}",
      // commit_key_it->first);
    }
  };
}