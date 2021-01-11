// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/spin_lock.h"
#include "kv/kv_types.h"
#include "node/new_ledger_secrets.h" // TODO: Bad!
#include "tls/entropy.h"

#include <algorithm>
#include <map>

namespace kv
{
  template <typename T>
  class NewTxEncryptor : public AbstractTxEncryptor
  {
  private:
    SpinLock lock;
    std::shared_ptr<T> ledger_secrets;
    bool is_recovery = false;

    void set_iv(
      crypto::GcmHeader<crypto::GCM_SIZE_IV>& gcm_hdr,
      Version version,
      Term term,
      bool is_snapshot = false)
    {
      // IV is function of seqno, term and snapshot so that:
      // - Seqno reuse across rollbacks does not reuse IV
      // - Snapshots do not reuse IV
      // - If all nodes execute the _same_ tx (or generate the same snapshot),
      // the same IV will be used

      gcm_hdr.set_iv_seq(version);
      gcm_hdr.set_iv_term(term);
      gcm_hdr.set_iv_snapshot(is_snapshot);
    }

    // TODO: How to avoid mentioning NewLedgerSecret here??
    // This should return the crypto::AESGCM context directly!
    std::shared_ptr<ccf::NewLedgerSecret> get_encryption_key(Version version)
    {
      std::lock_guard<SpinLock> guard(lock);
      // TODO: Optimisation here, we can use the latest key directly, as long as
      // the last key is valid for the target version

      return ledger_secrets->get_encryption_key_it(version)->second;
    }

  public:
    NewTxEncryptor(std::shared_ptr<T> secrets, bool is_recovery_ = false) :
      ledger_secrets(secrets),
      is_recovery(is_recovery_)
    {}

    void update_encryption_key(
      Version version, std::vector<uint8_t>&& key) override
    {
      std::lock_guard<SpinLock> guard(lock);
      ledger_secrets->update_encryption_key(version, std::move(key));
    }

    void disable_recovery() override
    {
      is_recovery = false;
    }

    size_t get_header_length() override
    {
      return crypto::GcmHeader<crypto::GCM_SIZE_IV>::RAW_DATA_SIZE;
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
      crypto::GcmHeader<crypto::GCM_SIZE_IV> gcm_hdr;
      cipher.resize(plain.size());

      set_iv(gcm_hdr, version, term, is_snapshot);

      {
        std::lock_guard<SpinLock> guard(lock);
        ledger_secrets->get_encryption_key_for(version)->encrypt(
          gcm_hdr.get_iv(), plain, additional_data, cipher.data(), gcm_hdr.tag);
      }

      serialised_header = gcm_hdr.serialise();
    }

    bool decrypt(
      const std::vector<uint8_t>& cipher,
      const std::vector<uint8_t>& additional_data,
      const std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& plain,
      Version version) override
    {
      crypto::GcmHeader<crypto::GCM_SIZE_IV> gcm_hdr;
      gcm_hdr.deserialise(serialised_header);
      plain.resize(cipher.size());

      std::lock_guard<SpinLock> guard(lock);
      auto ret = ledger_secrets->get_encryption_key_for(version)->decrypt(
        gcm_hdr.get_iv(), gcm_hdr.tag, cipher, additional_data, plain.data());
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
      std::lock_guard<SpinLock> guard(lock);
      ledger_secrets->rollback(version);
    }

    void compact(Version version) override
    {
      // Advances the commit point to version, so that encryption keys that
      // will no longer be used are not considered when selecting an encryption
      // key.
      // Note: Encryption keys are still kept in memory to be passed on to new
      // nodes joining the service.
      std::lock_guard<SpinLock> guard(lock);

      if (!is_recovery)
      {
        LOG_FAIL_FMT("Compacting encryptor at {}...", version); // TODO: Delete
        // Do not compact ledger secrets on recovery, as all historical secrets
        // are used to decrypt the historical ledger
        ledger_secrets->compact(version);
      }
    }
  };
}