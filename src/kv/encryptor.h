// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/spin_lock.h"
#include "kv/kv_types.h"

namespace kv
{
  class TxEncryptor : public kv::AbstractTxEncryptor
  {
  public:
    struct KeyInfo
    {
      kv::Version version;

      // This is unfortunate. Because the encryptor updates the ledger secrets
      // on global hook, we need easy access to the raw secrets.
      std::vector<uint8_t> raw_key;
    };

  private:
    SpinLock lock;

    virtual void set_iv(
      crypto::GcmHeader<crypto::GCM_SIZE_IV>& gcm_hdr,
      kv::Version version,
      bool is_snapshot = false)
    {
      // Warning: The same IV will get re-used on rollback!
      gcm_hdr.set_iv_seq(version);
      gcm_hdr.set_iv_term(iv_id);
      gcm_hdr.set_iv_snapshot(is_snapshot);
    }

    const crypto::KeyAesGcm& get_encryption_key(kv::Version version)
    {
      std::lock_guard<SpinLock> guard(lock);

      // Encryption key for a given version is the one with the highest version
      // that is lower than the given version (e.g. if encryption_keys contains
      // two keys for version 0 and 10 then the key associated with version 0
      // is used for version [0..9] and version 10 for versions 10+)
      auto search = std::upper_bound(
        encryption_keys.rbegin(),
        encryption_keys.rend(),
        version,
        [](kv::Version a, EncryptionKey const& b) { return b.version <= a; });

      if (search == encryption_keys.rend())
      {
        throw std::logic_error(fmt::format(
          "TxEncryptor: encrypt version is not valid: {}", version));
      }

      return search->key;
    }

  protected:
    // Encryption keys are set when TxEncryptor object is created and are used
    // to determine which key to use for encryption/decryption when
    // committing/deserialising depending on the version

    struct EncryptionKey : KeyInfo
    {
      crypto::KeyAesGcm key;
    };

    std::list<EncryptionKey> encryption_keys;
    size_t iv_id = 0;

    virtual void record_compacted_keys(const std::list<KeyInfo>&){};

  public:
    TxEncryptor(const std::list<KeyInfo>& existing_keys)
    {
      // Create map of existing encryption keys from the recorded ledger secrets
      for (auto const& s : existing_keys)
      {
        encryption_keys.emplace_back(TxEncryptor::EncryptionKey{
          {s.version, s.raw_key}, crypto::KeyAesGcm(s.raw_key)});
      }
    }

    /**
     * Encrypt data and return serialised GCM header and cipher.
     *
     * @param[in]   plain             Plaintext to encrypt
     * @param[in]   additional_data   Additional data to tag
     * @param[out]  serialised_header Serialised header (iv + tag)
     * @param[out]  cipher            Encrypted ciphertext
     * @param[in]   version           Version used to retrieve the corresponding
     * encryption key
     * @param[in]   is_snapshot       Indicates that the entry is a snapshot (to
     * avoid IV re-use)
     */
    void encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      kv::Version version,
      kv::Term term,
      bool is_snapshot = false) override
    {
      crypto::GcmHeader<crypto::GCM_SIZE_IV> gcm_hdr;
      cipher.resize(plain.size());

      set_iv(gcm_hdr, version, is_snapshot);

      get_encryption_key(version).encrypt(
        gcm_hdr.get_iv(), plain, additional_data, cipher.data(), gcm_hdr.tag);

      serialised_header = gcm_hdr.serialise();
    }

    /**
     * Decrypt cipher and return plaintext.
     *
     * @param[in]   cipher            Cipher to decrypt
     * @param[in]   additional_data   Additional data to verify tag
     * @param[in]   serialised_header Serialised header (iv + tag)
     * @param[out]  plain             Decrypted plaintext
     * @param[in]   version           Version used to retrieve the corresponding
     * encryption key
     *
     * @return Boolean status indicating success of decryption.
     */
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

    void set_iv_id(size_t id)
    {
      iv_id = id;
    }

    /**
     * Return length of serialised header.
     *
     * @return size_t length of serialised header
     */
    size_t get_header_length() override
    {
      return crypto::GcmHeader<crypto::GCM_SIZE_IV>::RAW_DATA_SIZE;
    }

    void update_encryption_key(
      kv::Version version, std::vector<uint8_t>&& raw_ledger_key) override
    {
      std::lock_guard<SpinLock> guard(lock);

      LOG_DEBUG_FMT("Refreshing ledger encryption key at seqno {}", version);

      // encryption_keys.emplace_back(EncryptionKey{
      //   {version, raw_ledger_key}, crypto::KeyAesGcm(raw_ledger_key)});
    }

    void rollback(kv::Version version) override
    {
      std::lock_guard<SpinLock> guard(lock);

      while (encryption_keys.size() > 1)
      {
        auto k = encryption_keys.end();
        std::advance(k, -1);

        if (k->version <= version)
        {
          break;
        }

        encryption_keys.pop_back();
      }
    }

    void compact(kv::Version version) override
    {
      std::lock_guard<SpinLock> guard(lock);
      std::list<KeyInfo> compacted_keys;

      // Remove keys that have been superseded by a newer key.
      while (encryption_keys.size() > 1)
      {
        auto k = encryption_keys.begin();

        if (std::next(k)->version > version)
        {
          break;
        }

        compacted_keys.emplace_back(
          KeyInfo{std::next(k)->version, std::next(k)->raw_key});

        if (k->version < version)
        {
          encryption_keys.pop_front();
        }
      }

      record_compacted_keys(compacted_keys);
    }
  };
}