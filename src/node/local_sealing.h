// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/json.h"
#include "ccf/ds/logger.h"
#include "ccf/kv/version.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/snp_ioctl.h"
#include "ds/ccf_assert.h"
#include "ds/files.h"
#include "node/ledger_secret.h"
#include "node/ledger_secrets.h"

#include <algorithm>
#include <filesystem>
#include <fmt/format.h>
#include <map>
#include <optional>
#include <ranges>

namespace ccf
{

  inline std::string get_sealing_filename(const kv::Version& version)
  {
    return fmt::format("{}.sealed", version);
  }

  inline bool is_sealed_path(const std::string& path)
  {
    return path.ends_with(".sealed");
  }

  inline std::string get_aad_filename(const kv::Version& version)
  {
    return fmt::format("{}.aad", version);
  }

  inline bool is_aad_path(const std::string& path)
  {
    return path.ends_with(".aad");
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
    const std::vector<uint8_t>& sealed_text,
    const std::span<uint8_t>& aad)
  {
    ccf::crypto::check_supported_aes_key_size(raw_key.size() * 8);
    auto key = ccf::crypto::make_key_aes_gcm(raw_key);

    crypto::GcmCipher cipher;
    cipher.deserialise(sealed_text);

    std::vector<uint8_t> plaintext;
    if (!key->decrypt(
          cipher.hdr.get_iv(), cipher.hdr.tag, cipher.cipher, aad, plaintext))
    {
      throw std::logic_error("Failed to decrypt sealed text");
    }

    return plaintext;
  }

  struct SealedLedgerSecretAAD
  {
    ccf::kv::Version version = 0;
    ccf::pal::snp::TcbVersion tcb_version = {};
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SealedLedgerSecretAAD);
  DECLARE_JSON_REQUIRED_FIELDS(SealedLedgerSecretAAD);
  DECLARE_JSON_OPTIONAL_FIELDS(SealedLedgerSecretAAD, version, tcb_version)

  inline void seal_ledger_secret_to_disk(
    const std::string& sealed_secret_dir,
    const ccf::pal::snp::TcbVersion& tcb_version,
    const kv::Version& version,
    const LedgerSecretPtr& ledger_secret)
  {
    LOG_INFO_FMT("Sealing ledger secret to {}", sealed_secret_dir);

    files::create_directory(sealed_secret_dir);

    std::string plaintext = nlohmann::json(ledger_secret).dump();
    std::vector<uint8_t> buf_plaintext(plaintext.begin(), plaintext.end());

    std::string plainaad =
      nlohmann::json(
        SealedLedgerSecretAAD{.version = version, .tcb_version = tcb_version})
        .dump();
    std::vector<uint8_t> buf_aad(plainaad.begin(), plainaad.end());

    // prevent unsealing if the TCB changes
    auto sealing_key = ccf::pal::snp::make_derived_key(tcb_version);
    crypto::GcmCipher sealed_secret =
      aes_gcm_sealing(sealing_key->get_raw(), buf_plaintext, buf_aad);

    auto dir_path = files::fs::path(sealed_secret_dir);
    auto sealing_path = dir_path / get_sealing_filename(version);
    files::dump(sealed_secret.serialise(), sealing_path);
    auto aad_path = dir_path / get_aad_filename(version);
    files::dump(plainaad, aad_path);
    LOG_INFO_FMT(
      "Sealing complete of ledger secret to {} and {}", sealing_path, aad_path);
  }

  inline LedgerSecretPtr unseal_ledger_secret_from_disk(
    const files::fs::path& ledger_secret_path, const files::fs::path& aad_path)
  {
    try
    {
      CCF_ASSERT(
        files::exists(ledger_secret_path),
        "Sealed previous ledger secret cannot be found");
      CCF_ASSERT(
        files::exists(aad_path),
        "Sealed previous ledger secret's AAD cannot be found");

      LOG_INFO_FMT(
        "Reading sealed previous service secret from {}", ledger_secret_path);
      std::vector<uint8_t> ciphertext = files::slurp(ledger_secret_path);
      std::vector<uint8_t> aad_raw = files::slurp(aad_path);
      SealedLedgerSecretAAD aad =
        nlohmann::json::parse(std::string(aad_raw.begin(), aad_raw.end()));

      // This call will fail if the CPU's TCB version is rolled back below the
      // sealed tcb_version
      auto sealing_key = ccf::pal::snp::make_derived_key(aad.tcb_version);
      auto buf_plaintext =
        aes_gcm_unsealing(sealing_key->get_raw(), ciphertext, aad_raw);
      auto json = nlohmann::json::parse(
        std::string(buf_plaintext.begin(), buf_plaintext.end()));
      LedgerSecret unsealed_ledger_secret;
      from_json(json, unsealed_ledger_secret);

      LOG_INFO_FMT("Successfully unsealed secret");

      return std::make_shared<LedgerSecret>(std::move(unsealed_ledger_secret));
    }
    catch (const std::logic_error& e)
    {
      LOG_FAIL_FMT(
        "Failed to unseal previous ledger secret from {}: {}",
        ledger_secret_path,
        e.what());
      return nullptr;
    }
  }

  inline LedgerSecretPtr find_and_unseal_ledger_secret_from_disk(
    const std::string& sealed_secret_dir, kv::Version max_version)
  {
    std::vector<std::pair<kv::Version, std::filesystem::path>> files;
    std::map<kv::Version, std::filesystem::path> files_map;
    for (auto f : files::fs::directory_iterator(sealed_secret_dir))
    {
      auto filename = f.path().filename();
      std::optional<kv::Version> ledger_version =
        version_of_filename(filename.string());
      if (
        is_sealed_path(filename) && ledger_version.has_value() &&
        ledger_version.value() <= max_version)
      {
        files_map[ledger_version.value()] = f.path();
      }
    }

    for (auto& [version, sealed_path] : std::ranges::reverse_view(files_map))
    {
      auto aad_path = sealed_path.parent_path() / get_aad_filename(version);
      if (!files::exists(aad_path))
      {
        LOG_FAIL_FMT(
          "AAD file {} does not exist for sealed ledger secret {}",
          aad_path,
          sealed_path);
        continue;
      }
      auto aad_raw = files::slurp(aad_path);
      SealedLedgerSecretAAD aad =
        nlohmann::json::parse(std::string(aad_raw.begin(), aad_raw.end()));
      if (aad.version != version)
      {
        LOG_FAIL_FMT(
          "AAD version {} does not match sealed ledger secret version {}",
          aad.version,
          version);
        continue;
      }

      auto unsealed = unseal_ledger_secret_from_disk(sealed_path, aad_path);
      if (unsealed != nullptr)
      {
        LOG_INFO_FMT(
          "Successfully unsealed ledger secret from {}", sealed_path.string());
        return unsealed;
      }
    }

    // No valid ledger secret has been unsealed
    throw std::logic_error(fmt::format(
      "Failed to unseal any ledger secret from {}", sealed_secret_dir));
  }
}
