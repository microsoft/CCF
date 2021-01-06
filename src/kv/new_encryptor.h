// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/spin_lock.h"
#include "kv/kv_types.h"
#include "tls/entropy.h"

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

    std::map<kv::Version, crypto::KeyAesGcm> encryption_keys;

    // TODO: Is returning a reference OK here? What about if the encryptor gets
    // compacted??
    const crypto::KeyAesGcm& get_encryption_key(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);

      // Encryption key for a given version is the one with the highest version
      // that is lower than the given version (e.g. if encryption_keys contains
      // two keys for version 0 and 10 then the key associated with version 0
      // is used for version [0..9] and version 10 for versions 10+)

      auto search = encryption_keys.upper_bound(version);
      if (search == encryption_keys.begin())
      {
        throw std::logic_error(fmt::format(
          "TxEncryptor: could not find ledger encryption key for seqno {}",
          version));
      }

      search--;

      LOG_FAIL_FMT("Found: {}", search->first);

      return search->second;
    }

  public:
    NewTxEncryptor()
    {
      // encryption_keys.emplace(
      //   first_version, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
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
    }

    size_t get_header_length() override
    {
      return crypto::GcmHeader<crypto::GCM_SIZE_IV>::RAW_DATA_SIZE;
    }

    void rollback(kv::Version version) override
    {
      // TODO: Rollback to version, discarding all keys later than version
    }

    void compact(kv::Version version) override
    {
      // TODO: Compact all keys earlier than version (with some caveats)
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