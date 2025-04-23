
#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/json.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/snp_ioctl.h"
#include "ds/files.h"
#include "node/ledger_secrets.h"

namespace ccf
{
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
    const std::string& sealed_secret_location,
    const ccf::pal::snp::TcbVersion& tcb_version,
    const kv::Version& version,
    const LedgerSecretPtr& ledger_secret)
  {
    LOG_INFO_FMT("Sealing ledger secret to {}", sealed_secret_location);

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

    files::dump(sealed_secret.serialise(), sealed_secret_location);
    files::dump(sealed_secret.serialise(), sealed_secret_location + ".aad");
    LOG_INFO_FMT("Sealing complete of ledger secret with version: {}", version);
  }

  inline LedgerSecretPtr unseal_ledger_secret_from_disk(
    std::string ledger_secret_path)
  {
    try
    {
      CCF_ASSERT(
        files::exists(ledger_secret_path),
        "Sealed previous ledger secret cannot be found");
      CCF_ASSERT(
        files::exists(ledger_secret_path + ".aad"),
        "Sealed previous ledger secret's AAD cannot be found");

      LOG_INFO_FMT(
        "Reading sealed previous service secret from {}", ledger_secret_path);
      std::vector<uint8_t> ciphertext = files::slurp(ledger_secret_path);
      std::vector<uint8_t> aad_raw = files::slurp(ledger_secret_path);
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
    catch (const std::exception& e)
    {
      throw std::logic_error(fmt::format(
        "Failed to unseal the previous ledger secret: {}", e.what()));
    }
  }
}
