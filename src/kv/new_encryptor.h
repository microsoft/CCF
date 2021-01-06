// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/spin_lock.h"
#include "kv/kv_types.h"
#include "tls/entropy.h"

#include <algorithm>
#include <map>

namespace kv
{
  class NewTxEncryptor : public AbstractTxEncryptor
  {
  private:
    static constexpr kv::Version first_version = 1;
    // TODO: This is the node ID.
    // TODO: The IV issue should be fixed so that the IV isn't used across
    // rollbacks!
    size_t iv_id = 0;

    SpinLock lock;

    // TODO: Probably has to be replaced with the existing LedgerSecrets class!
    // struct EncryptionKey
    // {
    //   // TODO: Template Encryptor so that KV doesn't depend on crypto!
    //   crypto::KeyAesGcm key;
    // };

    virtual void set_iv(
      crypto::GcmHeader<crypto::GCM_SIZE_IV>& gcm_hdr,
      kv::Version version,
      bool is_snapshot = false)
    {
      // Warning: The same IV will get re-used on rollback!
      gcm_hdr.set_iv_seq(version);
      gcm_hdr.set_iv_id(iv_id);
      gcm_hdr.set_iv_snapshot(is_snapshot);
    }

    using EncryptionKeys = std::map<kv::Version, crypto::KeyAesGcm>;
    EncryptionKeys encryption_keys;
    EncryptionKeys::iterator it_compacted_key = encryption_keys.end();

    // TODO: Is returning a reference OK here? What about if the encryptor gets
    // compacted??
    const crypto::KeyAesGcm& get_encryption_key(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);

      // Encryption key for a given version is the one with the highest version
      // that is lower than the given version (e.g. if encryption_keys contains
      // two keys for version 0 and 10 then the key associated with version 0
      // is used for version [0..9] and version 10 for versions 10+)

      // TODO: Optimisation here, we can use the latest key directly, as long as
      // the last key is valid for the target version

      auto search = std::upper_bound(
        it_compacted_key,
        encryption_keys.end(),
        version,
        [](auto a, auto const& b) { return b.first > a; });
      if (search == it_compacted_key)
      {
        throw std::logic_error(fmt::format(
          "TxEncryptor: could not find ledger encryption key for seqno {}",
          version));
      }
      --search;

      LOG_FAIL_FMT("Found: {}", search->first);

      return search->second;
    }

  public:
    NewTxEncryptor(const std::vector<uint8_t>& key)
    {
      encryption_keys.emplace(first_version, key);
      it_compacted_key = encryption_keys.begin();
    }

    void update_encryption_key(
      kv::Version version, const std::vector<uint8_t>& key) override
    {
      std::lock_guard<SpinLock> guard(lock);

      CCF_ASSERT_FMT(
        encryption_keys.find(version) == encryption_keys.end(),
        "Encryption key at {} already exists",
        version);
      encryption_keys.emplace(version, key);

      LOG_TRACE_FMT("Added new encryption key at seqno {}", version);
    }

    size_t get_header_length() override
    {
      return crypto::GcmHeader<crypto::GCM_SIZE_IV>::RAW_DATA_SIZE;
    }

    void rollback(kv::Version version) override
    {
      // Rolls back all encryption keys more recent than version.
      // Note: Because the store is not locked while the serialisation (and
      // encryption) of a transaction occurs, if a rollback occurs after a
      // transaction is committed but not yet serialised, it is possible that
      // the transaction is serialised with the wrong encryption key (i.e. the
      // latest one after rollback). This is OK as the transaction replication
      // will fail.
      std::lock_guard<SpinLock> guard(lock);

      while (encryption_keys.size() > 1)
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

    void compact(kv::Version version) override
    {
      // Advances the compacted point to version, so that encryption keys that
      // will no longer be used are not considered when selecting an encryption
      // key.
      // Note: Encryption keys are still kept in memory to be passed on to new
      // nodes joining the service.
      std::lock_guard<SpinLock> guard(lock);

      auto search = std::upper_bound(
        it_compacted_key,
        encryption_keys.end(),
        version,
        [](auto a, auto const& b) { return b.first > a; });
      if (search == it_compacted_key)
      {
        throw std::logic_error(fmt::format(
          "TxEncryptor: could not find ledger encryption key for seqno {}",
          version));
      }

      it_compacted_key = --search;
      LOG_TRACE_FMT(
        "First usable encryption key is now at seqno {}",
        it_compacted_key->first);
    }

    void set_iv_id(size_t id) override
    {
      iv_id = id;
    }

    void encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      kv::Version version,
      bool is_snapshot = false) override
    {
      crypto::GcmHeader<crypto::GCM_SIZE_IV> gcm_hdr;
      cipher.resize(plain.size());

      set_iv(gcm_hdr, version, is_snapshot);

      get_encryption_key(version).encrypt(
        gcm_hdr.get_iv(), plain, additional_data, cipher.data(), gcm_hdr.tag);

      serialised_header = gcm_hdr.serialise();
    }

    bool decrypt(
      const std::vector<uint8_t>& cipher,
      const std::vector<uint8_t>& additional_data,
      const std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& plain,
      kv::Version version) override
    {
      crypto::GcmHeader<crypto::GCM_SIZE_IV> gcm_hdr;
      gcm_hdr.deserialise(serialised_header);
      plain.resize(cipher.size());

      auto ret = get_encryption_key(version).decrypt(
        gcm_hdr.get_iv(), gcm_hdr.tag, cipher, additional_data, plain.data());

      if (!ret)
      {
        plain.resize(0);
      }

      return ret;
    }
  };

}