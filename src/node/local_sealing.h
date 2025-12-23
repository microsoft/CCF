// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/hkdf.h"
#include "ccf/crypto/md_type.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/rsa_public_key.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/json.h"
#include "ccf/entity_id.h"
#include "ccf/kv/version.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/snp_ioctl.h"
#include "ccf/service/node_info.h"
#include "ds/ccf_assert.h"
#include "ds/files.h"
#include "ds/internal_logger.h"
#include "node/ledger_secret.h"
#include "node/ledger_secrets.h"
#include "node/share_manager.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fmt/format.h>
#include <map>
#include <optional>
#include <ranges>

namespace ccf
{

  inline std::string get_sealing_filename(const kv::Version& version)
  {
    return fmt::format("{}.sealed.json", version);
  }

  inline std::optional<kv::Version> version_of_filename(const std::string& path)
  {
    auto pos = path.find_first_of('.');
    if (pos == std::string::npos)
    {
      throw std::logic_error(fmt::format(
        "Sealed ledger secret file name {} does not contain a version", path));
    }

    try
    {
      return std::stol(path.substr(0, pos));
    }
    catch (const std::invalid_argument& e)
    {
      LOG_FAIL_FMT(
        "Unable to parse version from file name {}, {}", path, e.what());
      return std::nullopt;
    }
  }

  inline crypto::GcmCipher aes_gcm_sealing(
    std::span<const uint8_t> raw_key,
    std::span<const uint8_t> plaintext,
    const std::span<uint8_t>& aad)
  {
    ccf::crypto::check_supported_aes_key_size(raw_key.size() * 8);
    auto key = ccf::crypto::make_key_aes_gcm(raw_key);

    crypto::GcmCipher cipher(plaintext.size());
    cipher.hdr.set_random_iv();

    key->encrypt(cipher.hdr.iv, plaintext, aad, cipher.cipher, cipher.hdr.tag);
    return cipher;
  }

  inline std::vector<uint8_t> aes_gcm_unsealing(
    std::span<const uint8_t> raw_key,
    std::vector<uint8_t> sealed_text,
    std::span<const uint8_t> aad)
  {
    ccf::crypto::check_supported_aes_key_size(raw_key.size() * 8);
    auto key = ccf::crypto::make_key_aes_gcm(raw_key);

    crypto::GcmCipher cipher;
    cipher.deserialise(sealed_text);

    std::vector<uint8_t> plaintext;
    if (!key->decrypt(
          cipher.hdr.get_iv(), cipher.hdr.tag, cipher.cipher, aad, plaintext))
    {
      throw std::logic_error("Failed to decrypt sealed data");
    }

    return plaintext;
  }

  const std::string label = "CCF AMD Local Sealing Key";

  inline std::vector<uint8_t> derive_sealing_key(
    const ccf::pal::snp::TcbVersionRaw& tcb_version, int version)
  {
    switch (version)
    {
      case 1:
      {
        auto derived_key = ccf::pal::snp::make_derived_key(tcb_version);
        std::vector<uint8_t> salt = {};
        std::vector<uint8_t> info(label.begin(), label.end());
        auto sealing_key = crypto::hkdf(
          crypto::MDType::SHA256, 256, derived_key->get_raw(), salt, info);

        return sealing_key;
      }
      default:
      {
        throw std::logic_error(fmt::format(
          "Unsupported sealing key derivation version {}", version));
      }
    }
  }

  inline SealedRecoveryKey get_sealed_recovery_key(
    std::span<const uint8_t> derived_key)
  {
    auto recovery_key_pair = crypto::make_ec_key_pair();
    auto recovery_pubkey = recovery_key_pair->public_key_pem();
    auto recovery_privkey = recovery_key_pair->private_key_pem();

    std::span<uint8_t> plaintext(
      recovery_privkey.data(), recovery_privkey.size());
    std::span<uint8_t> aad(recovery_pubkey.data(), recovery_pubkey.size());

    crypto::GcmCipher sealed_key = aes_gcm_sealing(derived_key, plaintext, aad);

    SealedRecoveryKey res = {
      .version = 1,
      .ciphertext = sealed_key.serialise(),
      .pubkey = recovery_pubkey};

    // TODO openssl cleanse plaintext?
    return res;
  }

  inline crypto::ECKeyPairPtr unseal_recovery_key(
    std::span<uint8_t> derived_key, const SealedRecoveryKey& sealed_key)
  {
    std::span<const uint8_t> aad(
      sealed_key.pubkey.data(), sealed_key.pubkey.size());

    auto plain = aes_gcm_unsealing(derived_key, sealed_key.ciphertext, aad);
    crypto::Pem pem(plain.data(), plain.size());

    return crypto::make_ec_key_pair(pem);
  }

  struct WrappedSealedLedgerSecret
  {
    std::vector<uint8_t> wrapped_latest_ledger_secret;
    std::map<NodeId, std::vector<uint8_t>> encrypted_wrapping_keys;
  };

  inline void seal_ledger_secret(
    ccf::kv::Tx& tx, const LedgerSecretPtr& latest_ledger_secret)
  {
    // TODO don't use the shared ledger secret wrapping key?
    auto ls_wrapping_key = SharedLedgerSecretWrappingKey(1, 1);
    auto encrypted_wrapping_keys = std::map<NodeId, std::vector<uint8_t>>();
    for (const auto& [node_id, node_info] :
         InternalTablesAccess::get_trusted_nodes(tx))
    {
      if (node_info.sealed_recovery_key.has_value())
      {
        auto sealed_recovery_key = node_info.sealed_recovery_key.value();
        auto node_enc_pubk =
          ccf::crypto::make_rsa_public_key(sealed_recovery_key.pubkey);
        std::vector<uint8_t> full_share_serialised(
          (ccf::crypto::sharing::Share::serialised_size));
        ls_wrapping_key.get_full_share_serialised(full_share_serialised);
        encrypted_wrapping_keys[node_id] =
          node_enc_pubk->rsa_oaep_wrap(full_share_serialised);
        OPENSSL_cleanse(
          full_share_serialised.data(), full_share_serialised.size());
      }
    }
    WrappedSealedLedgerSecret wrapped_sealed_ledger_secret = {
      .wrapped_latest_ledger_secret =
        ls_wrapping_key.wrap(latest_ledger_secret),
      .encrypted_wrapping_keys = encrypted_wrapping_keys};
    // TODO set the relevant table
  }

  inline LedgerSecretPtr unseal_ledger_secret(
    ccf::kv::ReadOnlyTx& tx, const NodeId& node_id)
  {
    throw std::logic_error("Not implemented");
  }
