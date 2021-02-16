// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "secrets.h"
#include "shares.h"
#include "tls/entropy.h"

namespace ccf
{
  struct LedgerSecret
  {
    std::vector<uint8_t> raw_key;
    std::shared_ptr<crypto::KeyAesGcm> key;

    std::optional<kv::Version> previous_secret_stored_version = std::nullopt;

    bool operator==(const LedgerSecret& other) const
    {
      return raw_key == other.raw_key &&
        previous_secret_stored_version == other.previous_secret_stored_version;
    }

    LedgerSecret() = default;

    // The copy construtor is used for serialising a LedgerSecret. However, only
    // the raw_key is serialised and other.key is nullptr so use raw_key to seed
    // key.
    LedgerSecret(const LedgerSecret& other) :
      raw_key(other.raw_key),
      key(std::make_shared<crypto::KeyAesGcm>(other.raw_key)),
      previous_secret_stored_version(other.previous_secret_stored_version)
    {
      LOG_FAIL_FMT("LedgerSecret copy constructor!");
    }

    LedgerSecret(
      std::vector<uint8_t>&& raw_key_,
      std::optional<kv::Version> previous_secret_stored_version_ =
        std::nullopt) :
      raw_key(raw_key_),
      key(std::make_shared<crypto::KeyAesGcm>(std::move(raw_key_))),
      previous_secret_stored_version(previous_secret_stored_version_)
    {
      LOG_FAIL_FMT(
        "Ledger secret copy, previous version: {}",
        previous_secret_stored_version_.value_or(kv::NoVersion));
    }
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(LedgerSecret)
  DECLARE_JSON_REQUIRED_FIELDS(LedgerSecret, raw_key)
  DECLARE_JSON_OPTIONAL_FIELDS(LedgerSecret, previous_secret_stored_version)

  using LedgerSecretPtr = std::shared_ptr<LedgerSecret>;

  inline LedgerSecretPtr make_ledger_secret()
  {
    LOG_FAIL_FMT("Making ledger secret!");

    return std::make_shared<LedgerSecret>(
      tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
  }

  inline std::vector<uint8_t> decrypt_previous_ledger_secret_raw(
    const LedgerSecretPtr& ledger_secret,
    std::vector<uint8_t>&& encrypted_previous_secret_raw)
  {
    crypto::GcmCipher encrypted_ls;
    encrypted_ls.deserialise(encrypted_previous_secret_raw);
    std::vector<uint8_t> decrypted_ls_raw(encrypted_ls.cipher.size());

    if (!ledger_secret->key->decrypt(
          encrypted_ls.hdr.get_iv(),
          encrypted_ls.hdr.tag,
          encrypted_ls.cipher,
          nullb,
          decrypted_ls_raw.data()))
    {
      throw std::logic_error("Decryption of previous ledger secret failed");
    }

    return decrypted_ls_raw;
  }
}

namespace nlohmann
{
  template <>
  struct adl_serializer<ccf::LedgerSecretPtr>
  {
    static void to_json(json& j, const ccf::LedgerSecretPtr& s)
    {
      if (s.get())
      {
        j = *s;
      }
      else
      {
        j = nullptr;
      }
    }

    static void from_json(const json& j, ccf::LedgerSecretPtr& s)
    {
      if (j.is_null())
      {
        s = nullptr;
      }
      else
      {
        // TODO: This seems that the following doesn't work. Investigate.
        // s = std::make_shared<ccf::LedgerSecret>(j);
        std::optional<kv::Version> previous_version;
        auto it = j.find("previous_secret_stored_version");
        if (it != j.end())
        {
          previous_version = *it;
        }
        s = std::make_shared<ccf::LedgerSecret>(
          j.at("raw_key"), previous_version);
      }
    }
  };
}