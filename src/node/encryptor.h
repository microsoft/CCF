// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmkey.h"
#include "entities.h"
#include "kv/kvtypes.h"
#include "node/ledgersecrets.h"

#include <atomic>
#include <list>

namespace ccf
{
  using SeqNo = uint64_t;

  // NullTxEncryptor does not decrypt or verify integrity
  class NullTxEncryptor : public kv::AbstractTxEncryptor
  {
  public:
    void encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      kv::Version version) override
    {
      crypto::GcmHeader<crypto::GCM_SIZE_IV> gcm_hdr = {};
      serialised_header = std::move(gcm_hdr.serialise());
      cipher = plain;
    }

    bool decrypt(
      const std::vector<uint8_t>& cipher,
      const std::vector<uint8_t>& additional_data,
      const std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& plain,
      kv::Version version) override
    {
      plain = cipher;
      return true;
    }

    size_t get_header_length() override
    {
      return crypto::GcmHeader<crypto::GCM_SIZE_IV>::RAW_DATA_SIZE;
    }

    void update_encryption_key(
      kv::Version version, const std::vector<uint8_t>& raw_ledger_key) override
    {}

    void rollback(kv::Version version) override {}
    void compact(kv::Version version) override {}
  };

  class TxEncryptor : public kv::AbstractTxEncryptor
  {
  private:
    NodeId id;
    bool is_recovery;

    std::atomic<SeqNo> seqNo{0};
    SpinLock lock;

    std::shared_ptr<LedgerSecrets> ledger_secrets;

    // Encryption keys are set when TxEncryptor object is created and are used
    // to determine which key to use for encryption/decryption when
    // committing/deserialising depending on the version

    struct KeyInfo
    {
      kv::Version version;

      // This is unfortunate. Because the encryptor updates the ledger secrets
      // on global hook, we need easy access to the raw secrets.
      std::vector<uint8_t> raw_key;
    };

    struct EncryptionKey : KeyInfo
    {
      crypto::KeyAesGcm key;
    };

    std::list<EncryptionKey> encryption_keys;

    void set_iv(crypto::GcmHeader<crypto::GCM_SIZE_IV>& gcm_hdr)
    {
      gcm_hdr.set_iv_id(id);
      gcm_hdr.set_iv_seq(seqNo.fetch_add(1));
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

  public:
    TxEncryptor(
      NodeId id_,
      std::shared_ptr<LedgerSecrets> ls,
      bool is_recovery_ = false) :
      id(id_),
      ledger_secrets(ls),
      is_recovery(is_recovery_)
    {
      // Create map of existing encryption keys from the recorded ledger secrets
      for (auto const& s : ls->secrets_map)
      {
        encryption_keys.emplace_back(EncryptionKey{
          s.first,
          s.second.master,
          crypto::KeyAesGcm(s.second.master),
        });
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
     */
    void encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      kv::Version version) override
    {
      crypto::GcmHeader<crypto::GCM_SIZE_IV> gcm_hdr;
      cipher.resize(plain.size());

      // Set IV
      set_iv(gcm_hdr);

      get_encryption_key(version).encrypt(
        gcm_hdr.get_iv(), plain, additional_data, cipher.data(), gcm_hdr.tag);

      serialised_header = std::move(gcm_hdr.serialise());
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
        plain.resize(0);

      return ret;
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
      kv::Version version, const std::vector<uint8_t>& raw_ledger_key) override
    {
      std::lock_guard<SpinLock> guard(lock);

      encryption_keys.emplace_back(EncryptionKey{
        version, raw_ledger_key, crypto::KeyAesGcm(raw_ledger_key)});
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
      std::list<KeyInfo> keys_to_seal;

      // Remove keys that have been superseded by a newer key. News keys are
      // sealed on compact.
      while (encryption_keys.size() > 1)
      {
        auto k = encryption_keys.begin();

        if (std::next(k)->version > version)
        {
          break;
        }

        keys_to_seal.emplace_back(
          KeyInfo{std::next(k)->version, std::next(k)->raw_key});

        if (k->version < version)
        {
          encryption_keys.pop_front();
        }
      }

      if (!is_recovery)
      {
        for (auto const& k : keys_to_seal)
        {
          ledger_secrets->set_secret(k.version, k.raw_key);
          ledger_secrets->seal_secret(k.version);
        }
      }
    }
  };
}