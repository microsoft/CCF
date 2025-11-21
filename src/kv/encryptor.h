// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/hmac.h"
#include "kv/kv_types.h"

#include <algorithm>
#include <map>

namespace ccf::kv
{
  template <typename T, typename S>
  class TxEncryptor : public AbstractTxEncryptor
  {
  private:
    std::shared_ptr<T> ledger_secrets;

    void set_iv(S& hdr, TxID tx_id, EntryType entry_type = EntryType::WriteSet)
    {
      // IV is function of seqno, term and snapshot so that:
      // - Same seqno across rollbacks does not reuse IV
      // - Snapshots do not reuse IV
      // - If all nodes execute the _same_ tx (or generate the same snapshot),
      // the same IV will be used

      // Note that only the first 31 bits of the term are used for the IV which
      // is acceptable for a live CCF as 2^31 elections will take decades, even
      // with an election timeout as low as 1 sec.

      hdr.set_iv_seq(tx_id.seqno);
      hdr.set_iv_term(tx_id.view);
      if (entry_type == EntryType::Snapshot)
      {
        hdr.set_iv_is_snapshot();
      }
    }

  public:
    TxEncryptor(const std::shared_ptr<T>& secrets) : ledger_secrets(secrets) {}

    size_t get_header_length() override
    {
      return S::serialised_size();
    }

    uint64_t get_term(const uint8_t* data, size_t size) override
    {
      S s;
      s.deserialise(data, size);
      return s.get_term();
    }

    /**
     * Encrypt data and return serialised GCM header and cipher.
     *
     * @param[in]   plain             Plaintext to encrypt
     * @param[in]   additional_data   Additional data to tag
     * @param[out]  serialised_header Serialised header (iv + tag)
     * @param[out]  cipher            Encrypted ciphertext
     * encryption key
     * @param[in]   tx_id             Transaction ID (version + term)
     * corresponding with the plaintext
     * @param[in]   entry_type       Indicates the type of the entry to
     * avoid IV re-use
     * @param[in]   historical_hint   If true, considers all ledger secrets for
     * encryption. Otherwise, try to use the latest used secret (defaults to
     * false)
     *
     * @return Boolean status indicating success of encryption.
     */
    bool encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      const TxID& tx_id,
      EntryType entry_type = EntryType::WriteSet,
      bool historical_hint = false) override
    {
      S hdr;

      set_iv(hdr, tx_id, entry_type);

      auto key =
        ledger_secrets->get_encryption_key_for(tx_id.seqno, historical_hint);
      if (key == nullptr)
      {
        return false;
      }

      key->encrypt(hdr.get_iv(), plain, additional_data, cipher, hdr.tag);

      serialised_header = hdr.serialise();

      return true;
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
     * @param[out]   term             Term contained in header
     * @param[in]   historical_hint   If true, considers all ledger secrets for
     * decryption. Otherwise, try to use the latest used secret (defaults to
     * false)
     *
     * @return Boolean status indicating success of decryption.
     */
    bool decrypt(
      const std::vector<uint8_t>& cipher,
      const std::vector<uint8_t>& additional_data,
      const std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& plain,
      Version version,
      Term& term,
      bool historical_hint = false) override
    {
      S hdr;
      hdr.deserialise(serialised_header);
      term = hdr.get_term();

      auto key =
        ledger_secrets->get_encryption_key_for(version, historical_hint);
      if (key == nullptr)
      {
        return false;
      }

      auto ret =
        key->decrypt(hdr.get_iv(), hdr.tag, cipher, additional_data, plain);
      if (!ret)
      {
        plain.resize(0);
      }

      return ret;
    }

    ccf::crypto::HashBytes get_commit_nonce(
      const TxID& tx_id, bool historical_hint = false) override
    {
      auto secret =
        ledger_secrets->get_secret_for(tx_id.seqno, historical_hint);
      if (secret == nullptr)
      {
        throw std::logic_error("Failed to get encryption key");
      }
      auto txid_str = tx_id.to_str();
      std::vector<uint8_t> txid = {
        txid_str.data(), txid_str.data() + txid_str.size()};

      auto commit_nonce = ccf::crypto::hmac(
        ccf::crypto::MDType::SHA256, secret->get_commit_secret(), txid);
      return commit_nonce;
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