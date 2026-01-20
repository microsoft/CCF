// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/hmac.h"
#include "ccf/crypto/symmetric_key.h"
#include "kv/kv_types.h"
#include "service/tables/secrets.h"
#include "service/tables/shares.h"

#include <openssl/crypto.h>

namespace ccf
{
  // Unique label for deriving commit secrets from ledger secrets.
  // See logic in get_commit_secret() below for derivation implementation.
  // It is important that this label is _not_ re-used for other purposes,
  // nor changed during the lifetime of a ledger, to preserve the semantics of
  // commit evidence (i.e. their reveal implies an entry is committed).
  static constexpr uint8_t commit_secret_label_[] = {
    'C', 'o', 'm', 'm', 'i', 't', ' ', 'S'};
  static std::span<const uint8_t> commit_secret_label{
    commit_secret_label_, sizeof(commit_secret_label_)};
  struct LedgerSecret
  {
    std::vector<uint8_t> raw_key;
    std::shared_ptr<ccf::crypto::KeyAesGcm> key;
    std::optional<ccf::kv::Version> previous_secret_stored_version =
      std::nullopt;
    std::optional<ccf::crypto::HashBytes> commit_secret = std::nullopt;

    const ccf::crypto::HashBytes& get_commit_secret()
    {
      if (!commit_secret.has_value())
      {
        commit_secret = ccf::crypto::hmac(
          ccf::crypto::MDType::SHA256, raw_key, commit_secret_label);
      }
      return commit_secret.value();
    }

    bool operator==(const LedgerSecret& other) const
    {
      return raw_key == other.raw_key &&
        previous_secret_stored_version == other.previous_secret_stored_version;
    }

    LedgerSecret() = default;

    ~LedgerSecret()
    {
      OPENSSL_cleanse(raw_key.data(), raw_key.size());
    }

    // The copy constructor is used for serialising a LedgerSecret. However,
    // only the raw_key is serialised and other.key is nullptr so use raw_key to
    // seed key.
    LedgerSecret(const LedgerSecret& other) :
      raw_key(other.raw_key),
      key(ccf::crypto::make_key_aes_gcm(other.raw_key)),
      previous_secret_stored_version(other.previous_secret_stored_version)
    {}

    LedgerSecret(
      std::vector<uint8_t>&& raw_key_,
      std::optional<ccf::kv::Version> previous_secret_stored_version_ =
        std::nullopt) :
      raw_key(raw_key_),
      key(ccf::crypto::make_key_aes_gcm(std::move(raw_key_))),
      previous_secret_stored_version(previous_secret_stored_version_)
    {}
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(LedgerSecret);
  DECLARE_JSON_REQUIRED_FIELDS(LedgerSecret, raw_key);
  DECLARE_JSON_OPTIONAL_FIELDS(LedgerSecret, previous_secret_stored_version);

  using LedgerSecretPtr = std::shared_ptr<LedgerSecret>;

  inline LedgerSecretPtr make_ledger_secret()
  {
    return std::make_shared<LedgerSecret>(
      ccf::crypto::get_entropy()->random(ccf::crypto::GCM_DEFAULT_KEY_SIZE));
  }

  inline std::vector<uint8_t> decrypt_previous_ledger_secret_raw(
    const LedgerSecretPtr& ledger_secret,
    const std::vector<uint8_t>& encrypted_previous_secret_raw)
  {
    ccf::crypto::GcmCipher encrypted_ls;
    encrypted_ls.deserialise(encrypted_previous_secret_raw);
    std::vector<uint8_t> decrypted_ls_raw;

    if (!ledger_secret->key->decrypt(
          encrypted_ls.hdr.get_iv(),
          encrypted_ls.hdr.tag,
          encrypted_ls.cipher,
          {},
          decrypted_ls_raw))
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
      if (s.get() != nullptr)
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
        ccf::LedgerSecret ls = j;
        s = std::make_shared<ccf::LedgerSecret>(ls);
      }
    }
  };
}