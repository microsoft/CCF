// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "secrets.h"
#include "tls/entropy.h"

#include <algorithm>
#include <map>
#include <optional>

namespace ccf
{
  struct LedgerSecret
  {
    std::vector<uint8_t> raw_key;
    std::shared_ptr<crypto::KeyAesGcm> key;

    bool operator==(const LedgerSecret& other) const
    {
      return raw_key == other.raw_key;
    }

    LedgerSecret() = default;

    LedgerSecret(const LedgerSecret& other) :
      raw_key(other.raw_key),
      key(std::make_shared<crypto::KeyAesGcm>(other.raw_key))
    {}

    LedgerSecret(std::vector<uint8_t>&& raw_key_) :
      raw_key(raw_key_),
      key(std::make_shared<crypto::KeyAesGcm>(std::move(raw_key_)))
    {}
  };

  inline LedgerSecret make_ledger_secret()
  {
    return LedgerSecret(tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
  }

  using VersionedLedgerSecret = std::pair<kv::Version, LedgerSecret>;
  using LedgerSecretsMap = std::map<kv::Version, LedgerSecret>;

  struct VersionedLedgerSecrets
  {
    LedgerSecretsMap secrets;

    VersionedLedgerSecrets() = default;

    VersionedLedgerSecrets(LedgerSecretsMap&& secrets_) :
      secrets(std::move(secrets_))
    {}

    bool operator==(const VersionedLedgerSecrets& other) const
    {
      return secrets == other.secrets;
    }
  };

  class LedgerSecrets
  {
  private:
    Secrets& secrets_table;

    std::optional<NodeId> self = std::nullopt;

    SpinLock lock;
    VersionedLedgerSecrets ledger_secrets;
    std::optional<LedgerSecretsMap::iterator> commit_key_it = std::nullopt;

    LedgerSecretsMap::iterator get_encryption_key_it(kv::Version version)
    {
      // Encryption key for a given version is the one with the highest version
      // that is lower than the given version (e.g. if encryption_keys contains
      // two keys for version 0 and 10 then the key associated with version 0
      // is used for version [0..9] and version 10 for versions 10+)

      auto search_begin =
        commit_key_it.value_or(ledger_secrets.secrets.begin());

      auto search = std::upper_bound(
        search_begin,
        ledger_secrets.secrets.end(),
        version,
        [](auto a, const auto& b) { return b.first > a; });
      if (search == search_begin)
      {
        throw std::logic_error(fmt::format(
          "kv::TxEncryptor: could not find ledger encryption key for seqno {}",
          version));
      }
      return --search;
    }

    void take_dependency_on_secrets(kv::Tx& tx)
    {
      // Ledger secrets are not stored in the KV. Instead, they are
      // cached in a unique LedgerSecrets instance that can be accessed without
      // reading the KV. However, it is possible that the ledger secrets are
      // updated (e.g. rekey tx) concurrently to their access by another tx. To
      // prevent conflicts, accessing the ledger secrets require access to a tx
      // object, which must take a dependency on the secrets table.
      auto v = tx.get_view(secrets_table);

      // Taking a read dependency on the key at self, which would get updated on rekey
      if (!self.has_value())
      {
        throw std::logic_error(
          "Node id should be set before taking dependency on secrets table");
      }
      v->get(self.value());
    }

  public:
    LedgerSecrets(
      Secrets& secrets_table_, std::optional<NodeId> self_ = std::nullopt) :
      secrets_table(secrets_table_),
      self(self_)
    {}

    LedgerSecrets(
      Secrets& secrets_table,
      NodeId self_,
      VersionedLedgerSecrets&& ledger_secrets_) :
      secrets_table(secrets_table),
      self(self_),
      ledger_secrets(std::move(ledger_secrets_))
    {}

    void init(kv::Version initial_version = 1)
    {
      std::lock_guard<SpinLock> guard(lock);

      ledger_secrets.secrets.emplace(initial_version, make_ledger_secret());
    }

    void set_node_id(NodeId id)
    {
      if (self.has_value())
      {
        throw std::logic_error(
          "Node id has already been set on ledger secrets");
      }

      self = id;
    }

    VersionedLedgerSecret get_latest(kv::Tx& tx)
    {
      std::lock_guard<SpinLock> guard(lock);

      take_dependency_on_secrets(tx);

      if (ledger_secrets.secrets.empty())
      {
        throw std::logic_error(
          "Could not retrieve latest ledger secret: no secret set");
      }

      auto latest_ledger_secret = ledger_secrets.secrets.rbegin();
      return std::make_pair(
        latest_ledger_secret->first, latest_ledger_secret->second);
    }

    std::optional<LedgerSecret> get_penultimate(kv::Tx& tx)
    {
      std::lock_guard<SpinLock> guard(lock);

      take_dependency_on_secrets(tx);

      if (ledger_secrets.secrets.size() < 2)
      {
        return std::nullopt;
      }
      return std::next(ledger_secrets.secrets.rbegin())->second;
    }

    VersionedLedgerSecrets get(
      kv::Tx& tx, std::optional<kv::Version> up_to = std::nullopt)
    {
      std::lock_guard<SpinLock> guard(lock);

      take_dependency_on_secrets(tx);

      if (!up_to.has_value())
      {
        return ledger_secrets;
      }

      auto search = ledger_secrets.secrets.find(up_to.value());
      if (search == ledger_secrets.secrets.end())
      {
        throw std::logic_error(
          fmt::format("No ledger secrets at {}", up_to.has_value()));
      }

      LedgerSecretsMap retrieved_keys(ledger_secrets.secrets.begin(), ++search);

      return VersionedLedgerSecrets(std::move(retrieved_keys));
    }

    void restore_historical(LedgerSecretsMap&& restored_ledger_secrets)
    {
      std::lock_guard<SpinLock> guard(lock);

      if (
        restored_ledger_secrets.rbegin()->first >=
        ledger_secrets.secrets.begin()->first)
      {
        throw std::logic_error(fmt::format(
          "Last restored version {} is greater than first existing version {}",
          restored_ledger_secrets.rbegin()->first,
          ledger_secrets.secrets.begin()->first));
      }

      ledger_secrets.secrets.merge(restored_ledger_secrets);
      commit_key_it = ledger_secrets.secrets.begin();
    }

    auto get_encryption_key_for(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);
      return get_encryption_key_it(version)->second.key;
    }

    void set_secret(kv::Version version, LedgerSecret&& secret)
    {
      std::lock_guard<SpinLock> guard(lock);

      CCF_ASSERT_FMT(
        ledger_secrets.secrets.find(version) == ledger_secrets.secrets.end(),
        "Encryption key at {} already exists",
        version);

      ledger_secrets.secrets.emplace(version, std::move(secret));

      LOG_INFO_FMT("Added new encryption key at seqno {}", version);
    }

    void rollback(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);
      auto start = commit_key_it.value_or(ledger_secrets.secrets.begin());
      if (version < start->first)
      {
        LOG_FAIL_FMT(
          "Cannot rollback encryptor at {}: committed key is at {}",
          version,
          start->first);
        return;
      }

      while (std::distance(start, ledger_secrets.secrets.end()) > 1)
      {
        auto k = ledger_secrets.secrets.rbegin();
        if (k->first <= version)
        {
          break;
        }

        LOG_TRACE_FMT("Rollback encryption key at seqno {}", k->first);
        ledger_secrets.secrets.erase(k->first);
      }
    }

    void compact(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);
      if (ledger_secrets.secrets.empty())
      {
        return;
      }

      commit_key_it = get_encryption_key_it(version);
      LOG_TRACE_FMT(
        "First usable encryption key is now at seqno {}",
        commit_key_it.value()->first);
    }
  };
}
