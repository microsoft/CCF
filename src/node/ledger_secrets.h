// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "kv/tx.h"
#include "ledger_secret.h"
#include "secrets.h"
#include "shares.h"

#include <algorithm>
#include <map>
#include <optional>

namespace ccf
{
  using LedgerSecretsMap = std::map<kv::Version, LedgerSecretPtr>;
  using VersionedLedgerSecret = LedgerSecretsMap::value_type;

  class LedgerSecrets
  {
  private:
    SpinLock lock;
    LedgerSecretsMap ledger_secrets;

    std::optional<LedgerSecretsMap::iterator> last_used_secret_it =
      std::nullopt;

    LedgerSecretPtr get_secret_for_version(
      kv::Version version, bool historical_hint = false)
    {
      if (ledger_secrets.empty())
      {
        LOG_FAIL_FMT("Ledger secrets map is empty");
        return nullptr;
      }

      if (!historical_hint && last_used_secret_it.has_value())
      {
        // Fast path for non-historical queries as both primary and backup nodes
        // encryt/decrypt transactions in order, it is sufficient to keep an
        // iterator on the last used secret to access ledger secrets in constant
        // time.
        auto& last_used_secret_it_ = last_used_secret_it.value();
        if (
          std::next(last_used_secret_it_) != ledger_secrets.end() &&
          version >= std::next(last_used_secret_it_)->first)
        {
          // Across a rekey, start using the next key
          ++last_used_secret_it_;
        }

        return last_used_secret_it_->second;
      }

      // Slow path, e.g. for historical queries. The ledger secret used to
      // encrypt/decrypt a transaction at a given version is the one with the
      // highest version that is lower than the given version (e.g. if
      // ledger_secrets contains two keys for version 0 and 10 then the key
      // associated with version 0 is used for version [0..9] and version 10 for
      // versions 10+)
      auto search = std::upper_bound(
        ledger_secrets.begin(),
        ledger_secrets.end(),
        version,
        [](auto a, const auto& b) { return b.first > a; });

      if (search == ledger_secrets.begin())
      {
        LOG_FAIL_FMT("Could not find ledger secret for seqno {}", version);
        return nullptr;
      }

      if (!historical_hint)
      {
        // Only update the last secret iterator on non-historical queries so
        // that the fast path is always preserved for transactions on the main
        // store
        last_used_secret_it = std::prev(search);
      }

      return std::prev(search)->second;
    }

    void take_dependency_on_secrets(kv::ReadOnlyTx& tx)
    {
      // Ledger secrets are not stored in the KV. Instead, they are
      // cached in a unique LedgerSecrets instance that can be accessed
      // without reading the KV. However, it is possible that the ledger
      // secrets are updated (e.g. rekey tx) concurrently to their access by
      // another tx. To prevent conflicts, accessing the ledger secrets
      // require access to a tx object, which must take a dependency on the
      // secrets table.
      auto secrets = tx.ro<Secrets>(Tables::ENCRYPTED_LEDGER_SECRETS);
      secrets->get(0);
    }

  public:
    LedgerSecrets() = default;

    LedgerSecrets(LedgerSecretsMap&& ledger_secrets_) :
      ledger_secrets(std::move(ledger_secrets_))
    {}

    void init(kv::Version initial_version = 1)
    {
      std::lock_guard<SpinLock> guard(lock);

      ledger_secrets.emplace(initial_version, make_ledger_secret());
    }

    void adjust_previous_secret_stored_version(kv::Version version)
    {
      // To be able to lookup the last active ledger secret before the service
      // crashed, the ledger secret created after the public recovery is
      // complete should point to the version at which the past ledger secret
      // has just been written to the store. This can only be done once the
      // private recovery is complete.
      std::lock_guard<SpinLock> guard(lock);

      if (ledger_secrets.empty())
      {
        throw std::logic_error(
          "There should be at least one ledger secret to adjust");
      }

      ledger_secrets.rbegin()->second->previous_secret_stored_version = version;
    }

    bool is_empty()
    {
      std::lock_guard<SpinLock> guard(lock);

      return ledger_secrets.empty();
    }

    VersionedLedgerSecret get_first(kv::ReadOnlyTx& tx)
    {
      std::lock_guard<SpinLock> guard(lock);

      take_dependency_on_secrets(tx);

      if (ledger_secrets.empty())
      {
        throw std::logic_error(
          "Could not retrieve first ledger secret: no secret set");
      }

      return *ledger_secrets.begin();
    }

    VersionedLedgerSecret get_latest(kv::ReadOnlyTx& tx)
    {
      std::lock_guard<SpinLock> guard(lock);

      take_dependency_on_secrets(tx);

      if (ledger_secrets.empty())
      {
        throw std::logic_error(
          "Could not retrieve latest ledger secret: no secret set");
      }

      return *ledger_secrets.rbegin();
    }

    std::pair<VersionedLedgerSecret, std::optional<VersionedLedgerSecret>>
    get_latest_and_penultimate(kv::ReadOnlyTx& tx)
    {
      std::lock_guard<SpinLock> guard(lock);

      take_dependency_on_secrets(tx);

      if (ledger_secrets.empty())
      {
        throw std::logic_error(
          "Could not retrieve latest ledger secret: no secret set");
      }

      const auto& latest_ledger_secret = ledger_secrets.rbegin();
      if (ledger_secrets.size() < 2)
      {
        return std::make_pair(*latest_ledger_secret, std::nullopt);
      }
      return std::make_pair(
        *latest_ledger_secret, *std::next(latest_ledger_secret));
    }

    LedgerSecretsMap get(
      kv::ReadOnlyTx& tx, std::optional<kv::Version> up_to = std::nullopt)
    {
      std::lock_guard<SpinLock> guard(lock);

      take_dependency_on_secrets(tx);

      if (!up_to.has_value())
      {
        return ledger_secrets;
      }

      auto search = ledger_secrets.find(up_to.value());
      if (search == ledger_secrets.end())
      {
        throw std::logic_error(
          fmt::format("No ledger secrets at {}", up_to.has_value()));
      }

      return LedgerSecretsMap(ledger_secrets.begin(), ++search);
    }

    void restore_historical(LedgerSecretsMap&& restored_ledger_secrets)
    {
      std::lock_guard<SpinLock> guard(lock);

      if (
        !ledger_secrets.empty() &&
        restored_ledger_secrets.rbegin()->first >=
          ledger_secrets.begin()->first)
      {
        throw std::logic_error(fmt::format(
          "Last restored version {} is greater than first existing version "
          "{}",
          restored_ledger_secrets.rbegin()->first,
          ledger_secrets.begin()->first));
      }

      ledger_secrets.merge(restored_ledger_secrets);
    }

    std::shared_ptr<crypto::KeyAesGcm> get_encryption_key_for(
      kv::Version version, bool historical_hint = false)
    {
      std::lock_guard<SpinLock> guard(lock);
      auto ls = get_secret_for_version(version, historical_hint);
      if (ls == nullptr)
      {
        return nullptr;
      }
      return ls->key;
    }

    void set_secret(kv::Version version, LedgerSecretPtr&& secret)
    {
      std::lock_guard<SpinLock> guard(lock);

      CCF_ASSERT_FMT(
        ledger_secrets.find(version) == ledger_secrets.end(),
        "Ledger secret at seqno {} already exists",
        version);

      ledger_secrets.emplace(version, std::move(secret));

      LOG_INFO_FMT("Added new ledger secret at seqno {}", version);
    }

    void rollback(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);
      if (ledger_secrets.empty())
      {
        return;
      }

      if (version < ledger_secrets.begin()->first)
      {
        LOG_FAIL_FMT(
          "Cannot rollback ledger secrets at {}: first secret is at {}",
          version,
          ledger_secrets.begin()->first);
        return;
      }

      while (ledger_secrets.size() > 1)
      {
        auto k = ledger_secrets.rbegin();
        if (k->first <= version)
        {
          break;
        }

        LOG_TRACE_FMT("Rollback ledger secrets at seqno {}", k->first);
        ledger_secrets.erase(k->first);
      }

      // Assume that the next operation will use the first non-rollbacked secret
      last_used_secret_it = std::prev(ledger_secrets.end());
    }
  };
}
