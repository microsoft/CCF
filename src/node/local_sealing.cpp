// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "local_sealing.h"

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/hkdf.h"
#include "ccf/crypto/md_type.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/rsa_public_key.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/entity_id.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/snp_ioctl.h"
#include "ccf/service/local_sealing.h"
#include "ccf/service/node_info.h"
#include "ds/ccf_assert.h"
#include "ds/internal_logger.h"
#include "node/ledger_secret.h"
#include "node/ledger_secrets.h"
#include "node/share_manager.h"
#include "service/internal_tables_access.h"
#include "service/tables/local_sealing.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fmt/format.h>
#include <map>
#include <openssl/crypto.h>
#include <optional>
#include <ranges>

namespace ccf::sealing
{
  crypto::GcmCipher aes_gcm_sealing(
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

  std::vector<uint8_t> aes_gcm_unsealing(
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

  std::vector<uint8_t> derive_snp_sealing_key(
    const ccf::pal::snp::TcbVersionRaw& tcb_version)
  {
    auto derived_key = ccf::pal::snp::make_derived_key(tcb_version);
    std::vector<uint8_t> salt = {};
    std::vector<uint8_t> info(
      LOCAL_SEALING_LABEL.begin(), LOCAL_SEALING_LABEL.end());
    auto sealing_key = crypto::hkdf(
      crypto::MDType::SHA256, 256, derived_key->get_raw(), salt, info);

    return sealing_key;
  }

  SealedRecoveryKey get_snp_sealed_recovery_key(
    const pal::snp::TcbVersionRaw& tcb_version)
  {
    auto derived_key = derive_snp_sealing_key(tcb_version);

    auto recovery_key_pair = crypto::make_ec_key_pair();
    auto recovery_pubkey = recovery_key_pair->public_key_pem();

    auto recovery_privkey = recovery_key_pair->private_key_pem();
    std::span<uint8_t> plaintext(
      recovery_privkey.data(), recovery_privkey.size());
    std::span<uint8_t> aad(recovery_pubkey.data(), recovery_pubkey.size());
    crypto::GcmCipher sealed_key = aes_gcm_sealing(derived_key, plaintext, aad);

    SealedRecoveryKey res = {
      .version = DerivedSealingKeyAlgorithm::SNP_v1,
      .ciphertext = sealed_key.serialise(),
      .pubkey = recovery_pubkey,
      .tcb_version = tcb_version};

    OPENSSL_cleanse(recovery_privkey.data(), recovery_privkey.size());
    return res;
  }

  EncryptedSealedSharesMap compute_encrypted_sealed_shares(
    ccf::kv::Tx& tx, const SharedLedgerSecretWrappingKey& ls_wrapping_key)
  {
    EncryptedSealedSharesMap encrypted_sealed_shares;

    auto trusted_nodes_info = InternalTablesAccess::get_trusted_nodes(tx);

    {
      std::vector<uint8_t> sealed_share_serialised(
        ccf::crypto::sharing::Share::serialised_size);
      ls_wrapping_key.get_full_share_serialised(sealed_share_serialised);

      for (const auto& [node_id, node_info] : trusted_nodes_info)
      {
        if (node_info.sealed_recovery_key.has_value())
        {
          auto sealed_recovery_key = node_info.sealed_recovery_key.value();
          auto node_enc_pubk =
            ccf::crypto::make_rsa_public_key(sealed_recovery_key.pubkey);
          encrypted_sealed_shares[node_id] =
            node_enc_pubk->rsa_oaep_wrap(sealed_share_serialised);
        }
      }
      OPENSSL_cleanse(
        sealed_share_serialised.data(), sealed_share_serialised.size());
    }
    return encrypted_sealed_shares;
  }

  crypto::RSAKeyPairPtr unseal_recovery_key(
    std::span<uint8_t> derived_key, const SealedRecoveryKey& sealed_key)
  {
    std::span<const uint8_t> aad(
      sealed_key.pubkey.data(), sealed_key.pubkey.size());

    auto plain = aes_gcm_unsealing(derived_key, sealed_key.ciphertext, aad);
    crypto::Pem pem(plain.data(), plain.size());

    return crypto::make_rsa_key_pair(pem);
  }

  void shuffle_sealed_shares(
    ccf::kv::Tx& tx, const LedgerSecretPtr& latest_ledger_secret)
  {
    auto ls_wrapping_key = SharedLedgerSecretWrappingKey(1, 1);
    auto wrapped_latest_ls = ls_wrapping_key.wrap(latest_ledger_secret);
    auto* sealed_ledger_secrets = tx.rw<SealedShares>(Tables::SEALED_SHARES);
    sealed_ledger_secrets->put(
      {wrapped_latest_ls,
       compute_encrypted_sealed_shares(tx, ls_wrapping_key),
       latest_ledger_secret->previous_secret_stored_version});
  }

  std::optional<LedgerSecretPtr> unseal_share(
    ccf::kv::ReadOnlyTx& tx, const NodeId& node_id)
  {
    // Retrieve the node's sealed recovery key
    auto* nodes = tx.ro<ccf::Nodes>(Tables::NODES);
    auto node_info_opt = nodes->get(node_id);
    if (!node_info_opt.has_value())
    {
      LOG_INFO_FMT(
        "Node {} was not in previous configuration to unseal recovery "
        "share",
        node_id);
      return std::nullopt;
    }
    auto& node_info = node_info_opt.value();
    if (!node_info.sealed_recovery_key.has_value())
    {
      LOG_INFO_FMT(
        "Node {} has no sealed recovery key to unseal recovery share", node_id);
      return std::nullopt;
    }
    auto sealed_recovery_key = node_info.sealed_recovery_key.value();

    // Retrieve the encrypted sealed share
    auto* sealed_shares = tx.ro<SealedShares>(Tables::SEALED_SHARES);
    if (!sealed_shares->get().has_value())
    {
      LOG_INFO_FMT("No sealed shares found to unseal recovery share");
      return std::nullopt;
    }
    auto sealed_share_info = sealed_shares->get().value();
    auto encrypted_full_share_it =
      sealed_share_info.encrypted_wrapping_keys.find(node_id);
    if (
      encrypted_full_share_it ==
      sealed_share_info.encrypted_wrapping_keys.end())
    {
      return std::nullopt;
    }
    auto encrypted_full_share = encrypted_full_share_it->second;

    // Unseal the recovery key pair
    std::vector<uint8_t> derived_key;
    switch (sealed_recovery_key.version)
    {
      case DerivedSealingKeyAlgorithm::SNP_v1:
        derived_key = derive_snp_sealing_key(sealed_recovery_key.tcb_version);
        break;
      default:
        throw std::logic_error("Unknown derived sealing key algorithm");
    }
    auto recovery_key_pair =
      unseal_recovery_key(derived_key, sealed_recovery_key);
    OPENSSL_cleanse(derived_key.data(), derived_key.size());

    // Decrypt the share
    auto decrypted_share =
      recovery_key_pair->rsa_oaep_unwrap(encrypted_full_share);
    ccf::crypto::sharing::Share share(decrypted_share);
    CCF_ASSERT_FMT(share.x == 0, "Expected full share when unsealing");
    ReconstructedLedgerSecretWrappingKey wrapping_key = {share};
    OPENSSL_cleanse(decrypted_share.data(), decrypted_share.size());

    // Unwrap the ledger secret
    return wrapping_key.unwrap(sealed_share_info.wrapped_latest_ledger_secret);
  }
}