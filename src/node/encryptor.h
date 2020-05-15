// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"
#include "kv/encryptor.h"
#include "node/ledger_secrets.h"

#include <atomic>
#include <list>

namespace ccf
{
  template <typename BaseEncryptor>
  class SeqTrackingMixin : public BaseEncryptor
  {
  private:
    std::atomic<size_t> seq_no{0};

    void set_iv(
      crypto::GcmHeader<crypto::GCM_SIZE_IV>& gcm_hdr,
      kv::Version version) override
    {
      gcm_hdr.set_iv_id(BaseEncryptor::iv_id);
      gcm_hdr.set_iv_seq(seq_no.fetch_add(1));
    }
  };

  template <typename BaseEncryptor>
  class LedgerSecretsMixin : public BaseEncryptor
  {
  private:
    bool is_recovery;
    std::shared_ptr<LedgerSecrets> ledger_secrets;

  protected:
    void record_compacted_keys(
      const std::list<kv::TxEncryptor::EncryptionKey::KeyInfo>& keys) override
    {
      if (!is_recovery)
      {
        for (auto const& k : keys)
        {
          ledger_secrets->add_new_secret(k.version, k.raw_key);
        }
      }
    }

  public:
    LedgerSecretsMixin(
      const std::shared_ptr<LedgerSecrets>& ls, bool is_recovery_ = false) :
      BaseEncryptor(ls->secrets_list),
      ledger_secrets(ls),
      is_recovery(is_recovery_)
    {}
  };

  using RaftTxEncryptor = LedgerSecretsMixin<SeqTrackingMixin<kv::TxEncryptor>>;
  using PbftTxEncryptor = LedgerSecretsMixin<kv::TxEncryptor>;
}