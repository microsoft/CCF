// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"

#include <algorithm>
#include <map>

namespace kv
{
  template <typename T, typename S>
  class TxEncryptor : public AbstractTxEncryptor
  {
  private:
    std::shared_ptr<T> ledger_secrets;

    void set_iv(S& hdr, TxID tx_id, bool is_snapshot = false)
    {
      // IV is function of seqno, term and snapshot so that:
      // - Same seqno across rollbacks does not reuse IV
      // - Snapshots do not reuse IV
      // - If all nodes execute the _same_ tx (or generate the same snapshot),
      // the same IV will be used

      // Note that only the first 31 bits of the term are used for the IV which
      // is acceptable for a live CCF as 2^31 elections will take decades, even
      // with an election timeout as low as 1 sec.

      hdr.set_iv_seq(tx_id.version);
      hdr.set_iv_term(tx_id.term);
      hdr.set_iv_snapshot(is_snapshot);
    }

  public:
    TxEncryptor(std::shared_ptr<T> secrets) : ledger_secrets(secrets) {}

    size_t get_header_length() override
    {
      return S::RAW_DATA_SIZE;
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
     * @param[in]   tx_id             Transaction ID (version + term)
     * corresponding with the plaintext
     * @param[in]   is_snapshot       Indicates that the entry is a snapshot (to
     * avoid IV re-use)
     */
    void encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      const TxID& tx_id,
      bool is_snapshot = false) override
    {
      S hdr;
      cipher.resize(plain.size());

      set_iv(hdr, tx_id, is_snapshot);

      ledger_secrets->get_encryption_key_for(tx_id.version)
        ->encrypt(hdr.get_iv(), plain, additional_data, cipher.data(), hdr.tag);

      serialised_header = hdr.serialise();
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
      Version version) override
    {
      S hdr;
      hdr.deserialise(serialised_header);
      plain.resize(cipher.size());

      auto ret = ledger_secrets->get_encryption_key_for(version)->decrypt(
        hdr.get_iv(), hdr.tag, cipher, additional_data, plain.data());
      if (!ret)
      {
        plain.resize(0);
      }

      return ret;
    }

    void rollback(Version version) override
    {
      // Rolls back all encryption keys more recent than version.
      // Note: Because the store is not locked while the serialisation (and
      // encryption) of a transaction occurs, if a rollback occurs after a
      // transaction is committed but not yet serialised, it is possible that
      // the transaction is serialised with the wrong encryption key (i.e. the
      // latest one after rollback). This is OK as the transaction replication
      // will fail.
      ledger_secrets->rollback(version);
    }
  };
}