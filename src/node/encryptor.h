// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmkey.h"
#include "entities.h"
#include "kv/kvtypes.h"
#include "node/ledgersecrets.h"

#include <atomic>

namespace ccf
{
  using SeqNo = uint64_t;

  // Warning: NullTxEncryptor does not encrypt or decrypt
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
  };

  class BaseTxEncryptor : public kv::AbstractTxEncryptor
  {
  private:
    NodeId id;
    std::atomic<SeqNo> seqNo{0};

    void set_iv(crypto::GcmHeader<crypto::GCM_SIZE_IV>& gcm_hdr)
    {
      gcm_hdr.set_iv_id(id);
      gcm_hdr.set_iv_seq(seqNo.fetch_add(1));
    }

    virtual const crypto::KeyAesGcm& get_encryption_key(
      kv::Version version) = 0;

  public:
    BaseTxEncryptor(NodeId id_) : id(id_) {}

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
      // TODO(#important,#TR): The key used for encrypting the ledger should be
      // different for each transaction (section V-A).
      crypto::GcmHeader<crypto::GCM_SIZE_IV> gcm_hdr;
      cipher.resize(plain.size());

      set_iv(gcm_hdr);

      LOG_FAIL_FMT("Encryption");
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

      LOG_FAIL_FMT("Decryption");
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
  };

  // The TxEncryptor is used for encrypting private transactions during normal
  // operation.
  class TxEncryptor : public BaseTxEncryptor
  {
  private:
    std::unique_ptr<crypto::KeyAesGcm> encryption_key;

    const crypto::KeyAesGcm& get_encryption_key(kv::Version version) override
    {
      return *encryption_key.get();
    }

  public:
    TxEncryptor(NodeId id_, LedgerSecrets& ls) :
      BaseTxEncryptor(id_),
      encryption_key(
        std::make_unique<crypto::KeyAesGcm>(ls.get_current().master))
    {}

    void update_encryption_key(LedgerSecret ls)
    {
      LOG_FAIL_FMT("Encryptor updated");
      encryption_key = std::make_unique<crypto::KeyAesGcm>(ls.master);
    }
  };

  // The RecoveryTxEncryptor is used during recovery to decrypt private ledger
  // entries. It contains the collection of ledger keys since the beginning of
  // time and uses the appropriate one based on the kv version.
  class RecoveryTxEncryptor : public BaseTxEncryptor
  {
  private:
    // Encryption keys are set when TxEncryptor object is created and are used
    // to determine which key to use for encryption/decryption when
    // committing/deserialising depending on the version
    std::vector<std::pair<kv::Version, crypto::KeyAesGcm>> encryption_keys;

  protected:
    const crypto::KeyAesGcm& get_encryption_key(kv::Version version) override
    {
      // Encryption key for a given version is the one with the highest version
      // that is lower than the given version (e.g. if encryption_keys contains
      // two keys for version 0 and 10 then the key associated with version 0
      // is used for version [0..9] and version 10 for versions 10+)
      auto search = std::upper_bound(
        encryption_keys.rbegin(),
        encryption_keys.rend(),
        version,
        [](kv::Version a, std::pair<kv::Version, crypto::KeyAesGcm> const& b) {
          return b.first <= a;
        });

      LOG_FAIL_FMT("size of encryption keys: {}", encryption_keys.size());

      LOG_FAIL_FMT("Using version {}, key {}", version, search->first);

      if (search == encryption_keys.rend())
      {
        throw std::logic_error(
          "TxEncryptor: encrypt version is not valid: " +
          std::to_string(version));
      }

      return search->second;
    }

  public:
    RecoveryTxEncryptor(NodeId id_, LedgerSecrets& ls) : BaseTxEncryptor(id_)
    {
      // Create map of existing encryption keys
      for (auto const& s : ls.get_secrets())
      {
        encryption_keys.emplace_back(std::make_pair(s.first, s.second->master));
      }
    }

    void update_encryption_key(kv::Version version, LedgerSecret ls)
    {
      LOG_FAIL_FMT("Encryptor updated, version {}", version);
      encryption_keys.emplace_back(std::make_pair(version, ls.master));
    }
  };
}