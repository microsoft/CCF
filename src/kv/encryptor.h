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
    bool is_recovery = false;

    void set_iv(S& hdr, Version version, Term term, bool is_snapshot = false)
    {
      // IV is function of seqno, term and snapshot so that:
      // - Same seqno across rollbacks does not reuse IV
      // - Snapshots do not reuse IV
      // - If all nodes execute the _same_ tx (or generate the same snapshot),
      // the same IV will be used

      hdr.set_iv_seq(version);
      hdr.set_iv_term(term);
      hdr.set_iv_snapshot(is_snapshot);
    }

  public:
    TxEncryptor(std::shared_ptr<T> secrets, bool is_recovery_ = false) :
      ledger_secrets(secrets),
      is_recovery(is_recovery_)
    {}

    void disable_recovery() override
    {
      is_recovery = false;
    }

    size_t get_header_length() override
    {
      return S::RAW_DATA_SIZE;
    }

    void encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      Version version,
      Term term,
      bool is_snapshot = false) override
    {
      S hdr;
      cipher.resize(plain.size());

      set_iv(hdr, version, term, is_snapshot);

      ledger_secrets->get_encryption_key_for(version)->encrypt(
        hdr.get_iv(), plain, additional_data, cipher.data(), hdr.tag);

      serialised_header = hdr.serialise();
    }

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

    void compact(Version version) override
    {
      // Advances the commit point to version, so that encryption keys that
      // will no longer be used are not considered when selecting an encryption
      // key.
      // Note: Encryption keys are still kept in memory to be passed on to new
      // nodes joining the service.

      // Do not compact ledger secrets on recovery, as all historical secrets
      // are used to decrypt the historical ledger
      if (!is_recovery)
      {
        ledger_secrets->compact(version);
      }
    }
  };
}