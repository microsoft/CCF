// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "kv/kv_types.h"
#include "secrets.h"
#include "tls/entropy.h"

#include <algorithm>
#include <map>
#include <optional>

namespace ccf
{
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

  class NewLedgerSecrets
  {
  public:
    // TODO: Move to accessor
    std::optional<EncryptionKeys::iterator> commit_key_it = std::nullopt;

  private:
    EncryptionKeys::iterator get_encryption_key_it(kv::Version version)
    {
      // Encryption key for a given version is the one with the highest version
      // that is lower than the given version (e.g. if encryption_keys contains
      // two keys for version 0 and 10 then the key associated with version 0
      // is used for version [0..9] and version 10 for versions 10+)

      LOG_FAIL_FMT("Search for key at {}", version);
      for (auto const& k : encryption_keys)
      {
        LOG_FAIL_FMT("Key at {}", k.first);
      }

      auto search_begin = commit_key_it.value_or(encryption_keys.begin());

      LOG_FAIL_FMT("Search begin at {}", search_begin->first);

      auto search = std::upper_bound(
        search_begin,
        encryption_keys.end(),
        version,
        [](auto a, const auto& b) { return b.first > a; });
      if (search == search_begin)
      {
        LOG_FAIL_FMT("No key for target seqno {}", version);
        throw std::logic_error(fmt::format(
          "kv::TxEncryptor: could not find ledger encryption key for seqno {}",
          version));
      }

      // TODO: Return --search directly
      auto ret = --search;
      LOG_FAIL_FMT("Using key for seqno: {}", ret->first);
      return ret;
    }

  public:
    EncryptionKeys encryption_keys;

    NewLedgerSecrets() = default;

    NewLedgerSecrets(const NewLedgerSecrets& other) :
      encryption_keys(other.encryption_keys)
    {}

    bool operator==(const NewLedgerSecrets& other) const
    {
      return encryption_keys == other.encryption_keys;
    }

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

    NewLedgerSecret get_latest()
    {
      if (encryption_keys.empty())
      {
        throw std::logic_error(
          "Could not retrieve latest ledger secret: no secret set");
      }
      LOG_FAIL_FMT(
        "Getting latest secret at {}", encryption_keys.rbegin()->first);
      return encryption_keys.rbegin()->second;
    }

    std::optional<NewLedgerSecret> get_penultimate()
    {
      if (encryption_keys.size() < 2)
      {
        return std::nullopt;
      }
      return std::next(encryption_keys.rbegin())->second;
    }

    NewLedgerSecret get_secret_at(kv::Version version)
    {
      auto search = encryption_keys.find(version);
      if (search == encryption_keys.end())
      {
        throw std::logic_error(
          fmt::format("Ledger secret at {} does not exist", version));
      }
      return search->second;
    }

    void rollback(kv::Version version)
    {
      auto start = commit_key_it.value_or(encryption_keys.begin());
      if (version < start->first)
      {
        LOG_FAIL_FMT(
          "Cannot rollback encryptor at {}: committed key is at {}",
          version,
          start->first);
        return;
      }

      while (std::distance(start, encryption_keys.end()) > 1)
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
      if (encryption_keys.empty())
      {
        return;
      }

      commit_key_it = get_encryption_key_it(version);
      LOG_TRACE_FMT(
        "First usable encryption key is now at seqno {}",
        commit_key_it.value()->first);
    }
  };

  class LedgerSecretsAccessor
  {
  private:
    SpinLock lock;
    Secrets& secrets_table;
    std::unique_ptr<NewLedgerSecrets> ledger_secrets;
    NodeId self;

    void take_dependency_on_secrets(kv::Tx& tx)
    {
      LOG_FAIL_FMT("Taking read dependency on secrets table!");
      auto v = tx.get_view(secrets_table);
      v->get(self);
    }

  public:
    LedgerSecretsAccessor(
      Secrets& secrets_table_,
      std::unique_ptr<NewLedgerSecrets> ledger_secrets_,
      NodeId self_) :
      secrets_table(secrets_table_),
      ledger_secrets(std::move(ledger_secrets_)),
      self(self_)
    {}

    void init(kv::Version initial_version = 1)
    {
      std::lock_guard<SpinLock> guard(lock);

      LOG_FAIL_FMT("Initialising ledger secrets at {}", initial_version);
      ledger_secrets->encryption_keys.emplace(
        initial_version, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
    }

    NewLedgerSecret get_latest(kv::Tx& tx)
    {
      std::lock_guard<SpinLock> guard(lock);

      take_dependency_on_secrets(tx);

      if (ledger_secrets->encryption_keys.empty())
      {
        throw std::logic_error(
          "Could not retrieve latest ledger secret: no secret set");
      }

      return ledger_secrets->encryption_keys.rbegin()->second;
    }

    std::optional<NewLedgerSecret> get_penultimate(kv::Tx& tx)
    {
      std::lock_guard<SpinLock> guard(lock);

      take_dependency_on_secrets(tx);

      if (ledger_secrets->encryption_keys.size() < 2)
      {
        return std::nullopt;
      }
      return std::next(ledger_secrets->encryption_keys.rbegin())->second;
    }

    NewLedgerSecrets get(kv::Tx& tx, kv::Version up_to = kv::NoVersion)
    {
      std::lock_guard<SpinLock> guard(lock);

      (void)up_to; // TODO: Fix: should be up to specific version

      take_dependency_on_secrets(tx);

      return *ledger_secrets;
    }

    void restore_historical(EncryptionKeys&& encryption_keys_)
    {
      std::lock_guard<SpinLock> guard(lock);

      // TODO: Assert than encryption_keys.begin() version is greater than
      // encryption_keys_.rbegin() version

      if (
        encryption_keys_.rbegin()->first >=
        ledger_secrets->encryption_keys.begin()->first)
      {
        throw std::logic_error(fmt::format(
          "Last restored version {} is greater than first existing version {}",
          encryption_keys_.rbegin()->first,
          ledger_secrets->encryption_keys.begin()->first));
      }

      LOG_FAIL_FMT(
        "Restoring {} keys", encryption_keys_.size()); // TODO: Remove
      ledger_secrets->encryption_keys.merge(encryption_keys_);

      ledger_secrets->commit_key_it = ledger_secrets->encryption_keys.begin();

      LOG_FAIL_FMT(
        "First search now at {}", ledger_secrets->commit_key_it.value()->first);
    }

    auto get_encryption_key_for(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);
      return ledger_secrets->get_encryption_key_for(version);
    }

    void set_encryption_key_for(kv::Version version, std::vector<uint8_t>&& key)
    {
      std::lock_guard<SpinLock> guard(lock);
      ledger_secrets->update_encryption_key(version, std::move(key));
    }

    void rollback(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);
      ledger_secrets->rollback(version);
    }

    void compact(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);
      ledger_secrets->compact(version);
    }
  };
}