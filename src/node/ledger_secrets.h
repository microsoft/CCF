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

    // The copy construtor is used for serialising a LedgerSecret. However, only
    // the raw_key is serialised and other.key is nullptr so use raw_key to seed
    // key.
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

  using LedgerSecretsMap = std::map<kv::Version, LedgerSecret>;
  using VersionedLedgerSecret = LedgerSecretsMap::value_type;

  class LedgerSecrets
  {
  private:
    std::optional<NodeId> self = std::nullopt;

    SpinLock lock;
    LedgerSecretsMap ledger_secrets;

    std::optional<LedgerSecretsMap::iterator> last_used_secret_it =
      std::nullopt;

    const LedgerSecret& get_secret_for_version(
      kv::Version version, bool historical_hint = false)
    {
      if (ledger_secrets.empty())
      {
        throw std::logic_error("Ledger secrets map is empty");
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
        throw std::logic_error(
          fmt::format("Could not find ledger secret for seqno {}", version));
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

      // Taking a read dependency on the key at self, which would get updated
      // on rekey
      if (!self.has_value())
      {
        throw std::logic_error(
          "Node id should be set before taking dependency on secrets table");
      }
      secrets->get(self.value());
    }

  public:
    LedgerSecrets(std::optional<NodeId> self_ = std::nullopt) : self(self_) {}

    LedgerSecrets(NodeId self_, LedgerSecretsMap&& ledger_secrets_) :
      self(self_),
      ledger_secrets(std::move(ledger_secrets_))
    {}

    void init(kv::Version initial_version = 1)
    {
      std::lock_guard<SpinLock> guard(lock);

      ledger_secrets.emplace(initial_version, make_ledger_secret());
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

      if (ledger_secrets.empty())
      {
        throw std::logic_error(
          "Could not retrieve latest ledger secret: no secret set");
      }

      return *ledger_secrets.rbegin();
    }

    std::pair<VersionedLedgerSecret, std::optional<VersionedLedgerSecret>>
    get_latest_and_penultimate(kv::Tx& tx)
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
      kv::Tx& tx, std::optional<kv::Version> up_to = std::nullopt)
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

    auto get_encryption_key_for(
      kv::Version version, bool historical_hint = false)
    {
      std::lock_guard<SpinLock> guard(lock);
      return get_secret_for_version(version, historical_hint).key;
    }

    void set_secret(kv::Version version, LedgerSecret&& secret)
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
