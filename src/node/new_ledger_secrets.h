// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "secrets.h"
#include "tls/base64.h" // TODO: Remove
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

  using VersionedLedgerSecret = std::pair<kv::Version, NewLedgerSecret>;
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

      auto search_begin = commit_key_it.value_or(encryption_keys.begin());

      auto search = std::upper_bound(
        search_begin,
        encryption_keys.end(),
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

  public:
    EncryptionKeys encryption_keys;

    NewLedgerSecrets() = default;

    NewLedgerSecrets(const NewLedgerSecrets& other) :
      encryption_keys(other.encryption_keys)
    {}

    NewLedgerSecrets(EncryptionKeys&& keys) : encryption_keys(std::move(keys))
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

    void print() const
    {
      LOG_FAIL_FMT("Encryption keys: {}", encryption_keys.size());
      for (auto const& e : encryption_keys)
      {
        LOG_FAIL_FMT("{}", tls::b64_from_raw(e.second.raw_key));
      }
    }
  };

  class LedgerSecretsAccessor
  {
  private:
    SpinLock lock;
    Secrets& secrets_table;
    std::unique_ptr<NewLedgerSecrets> ledger_secrets;

    std::optional<NodeId> self = std::nullopt;

    void take_dependency_on_secrets(kv::Tx& tx)
    {
      // Ledger secrets are not stored in the KV. Instead, they are
      // cached in a unique LedgerSecrets instance that can be accessed without
      // reading the KV. However, it is possible that the ledger secrets are
      // updated (e.g. rekey tx) concurrently to their access by another tx. To
      // prevent conflicts, accessing the ledger secrets require access to a tx
      // object, which must take a dependency on the secrets table.
      LOG_FAIL_FMT("Taking read dependency on secrets table!");
      auto v = tx.get_view(secrets_table);

      // Taking a depency on the key at self, which would get updated on rekey
      if (!self.has_value())
      {
        throw std::logic_error(
          "Node id should be set before taking dependency on secrets table");
      }
      v->get(self.value());
    }

  public:
    LedgerSecretsAccessor(
      Secrets& secrets_table_,
      std::unique_ptr<NewLedgerSecrets> ledger_secrets_,
      std::optional<NodeId> self_ = std::nullopt) :
      secrets_table(secrets_table_),
      ledger_secrets(std::move(ledger_secrets_)),
      self(self_)
    {}

    void init(kv::Version initial_version = 1)
    {
      std::lock_guard<SpinLock> guard(lock);

      ledger_secrets->encryption_keys.emplace(
        initial_version, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
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

      if (ledger_secrets->encryption_keys.empty())
      {
        throw std::logic_error(
          "Could not retrieve latest ledger secret: no secret set");
      }

      auto latest_ledger_secret = ledger_secrets->encryption_keys.rbegin();
      return std::make_pair(
        latest_ledger_secret->first, latest_ledger_secret->second);
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

    NewLedgerSecrets get(
      kv::Tx& tx, std::optional<kv::Version> up_to = std::nullopt)
    {
      std::lock_guard<SpinLock> guard(lock);

      take_dependency_on_secrets(tx);

      if (!up_to.has_value())
      {
        return *ledger_secrets;
      }

      auto search = ledger_secrets->encryption_keys.find(up_to.value());
      if (search == ledger_secrets->encryption_keys.end())
      {
        throw std::logic_error(
          fmt::format("No ledger secrets at {}", up_to.has_value()));
      }

      EncryptionKeys retrieved_keys(
        ledger_secrets->encryption_keys.begin(), ++search);

      LOG_FAIL_FMT("Retrieved keys count: {}", retrieved_keys.size());

      return NewLedgerSecrets(std::move(retrieved_keys));
    }

    void restore_historical(EncryptionKeys&& encryption_keys_)
    {
      std::lock_guard<SpinLock> guard(lock);

      if (
        encryption_keys_.rbegin()->first >=
        ledger_secrets->encryption_keys.begin()->first)
      {
        throw std::logic_error(fmt::format(
          "Last restored version {} is greater than first existing version {}",
          encryption_keys_.rbegin()->first,
          ledger_secrets->encryption_keys.begin()->first));
      }

      ledger_secrets->encryption_keys.merge(encryption_keys_);
      ledger_secrets->commit_key_it = ledger_secrets->encryption_keys.begin();
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

    void print() const
    {
      ledger_secrets->print();
    }
  };
}