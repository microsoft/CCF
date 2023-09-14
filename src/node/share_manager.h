// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/sha256.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/logger.h"
#include "crypto/sharing.h"
#include "kv/encryptor.h"
#include "ledger_secrets.h"
#include "network_state.h"
#include "secret_share.h"
#include "service/internal_tables_access.h"

#include <openssl/crypto.h>
#include <vector>

#define NEW_SSS

namespace ccf
{
  class LedgerSecretWrappingKey
  {
  private:
    static constexpr auto KZ_KEY_SIZE = crypto::GCM_DEFAULT_KEY_SIZE;
    bool has_wrapped = false;
    size_t num_shares;
    size_t recovery_threshold;
    std::vector<uint8_t> data; // Referred to as "kz" in TR
    std::vector<crypto::Share> shares;

  public:
#ifdef NEW_SSS
    LedgerSecretWrappingKey(size_t num_shares_, size_t recovery_threshold_) :
      num_shares(num_shares_),
      recovery_threshold(recovery_threshold_)
    {
      shares.resize(num_shares);
      crypto::Share secret;
      sample_secret_and_shares(secret, shares, recovery_threshold);
      LOG_DEBUG_FMT("YYY Split secret: {}", secret.to_str());
      data = secret.key(); // cleanse
    }
#else
    LedgerSecretWrappingKey(size_t num_shares_, size_t recovery_threshold_) :
      num_shares(num_shares_),
      recovery_threshold(recovery_threshold_),
      data(crypto::create_entropy()->random(KZ_KEY_SIZE))
    {}
#endif

#ifdef NEW_SSS
    LedgerSecretWrappingKey(
      std::vector<crypto::Share>&& shares_, size_t recovery_threshold_) :
      recovery_threshold(recovery_threshold_)
    {
      shares = shares_;
      crypto::Share secret;
      crypto::recover_secret(secret, shares, recovery_threshold - 1);
      LOG_DEBUG_FMT("YYY Recovered secret: {}", secret.to_str());
      data = secret.key(); // cleanse
    }
#else
    LedgerSecretWrappingKey(
      std::vector<SecretSharing::Share>& shares, size_t recovery_threshold_) :
      recovery_threshold(recovery_threshold_)
    {
      auto secret = SecretSharing::combine(shares, shares.size());
      data.resize(secret.size());
      std::copy_n(secret.begin(), secret.size(), data.begin());
      OPENSSL_cleanse(secret.data(), secret.size());
    }
#endif

    ~LedgerSecretWrappingKey()
    {
      OPENSSL_cleanse(data.data(), data.size());
    }

    size_t get_num_shares() const
    {
      return num_shares;
    }

    size_t get_recovery_threshold() const
    {
      return recovery_threshold;
    }

#ifdef NEW_SSS
    std::vector<std::vector<uint8_t>> get_shares() const
    {
      std::vector<std::vector<uint8_t>> shares_;
      for (const crypto::Share& share : shares)
      {
        LOG_INFO_FMT("YYY Share: {}", share.to_str());
        shares_.push_back(share.serialise());
      }
      return shares_;
    }
#else
    std::vector<SecretSharing::Share> get_shares() const
    {
      return SecretSharing::split(
        get_raw_data<SecretSharing::SplitSecret>(),
        get_num_shares(),
        get_recovery_threshold());
    }
#endif

    template <typename T>
    T get_raw_data() const
    {
      T ret;
      std::copy_n(data.begin(), data.size(), ret.begin());
      return ret;
    }

    std::vector<uint8_t> wrap(const LedgerSecretPtr& ledger_secret)
    {
      if (has_wrapped)
      {
        throw std::logic_error(
          "Ledger secret wrapping key has already wrapped once");
      }

      crypto::GcmCipher encrypted_ls(ledger_secret->raw_key.size());

      crypto::make_key_aes_gcm(data)->encrypt(
        encrypted_ls.hdr.get_iv(), // iv is always 0 here as the share wrapping
                                   // key is never re-used for encryption
        ledger_secret->raw_key,
        {},
        encrypted_ls.cipher,
        encrypted_ls.hdr.tag);

      has_wrapped = true;

      return encrypted_ls.serialise();
    }

    LedgerSecretPtr unwrap(
      const std::vector<uint8_t>& wrapped_latest_ledger_secret)
    {
      crypto::GcmCipher encrypted_ls;
      encrypted_ls.deserialise(wrapped_latest_ledger_secret);
      std::vector<uint8_t> decrypted_ls;

      if (!crypto::make_key_aes_gcm(data)->decrypt(
            encrypted_ls.hdr.get_iv(),
            encrypted_ls.hdr.tag,
            encrypted_ls.cipher,
            {},
            decrypted_ls))
      {
        throw std::logic_error("Unwrapping latest ledger secret failed");
      }

      return std::make_shared<LedgerSecret>(std::move(decrypted_ls));
    }
  };

  // During recovery, a list of EncryptedLedgerSecretInfo is constructed
  // from the local hook on the encrypted ledger secrets table.
  using RecoveredEncryptedLedgerSecrets = std::list<EncryptedLedgerSecretInfo>;

  // The ShareManager class provides the interface between the ledger secrets
  // object and the shares, ledger secrets and submitted shares KV tables. In
  // particular, it is used to:
  //  - Issue new recovery shares whenever required (e.g. on startup, rekey and
  //  membership updates)
  //  - Re-assemble the ledger secrets on recovery, once a threshold of members
  //  have successfully submitted their shares
  class ShareManager
  {
  private:
    std::shared_ptr<LedgerSecrets> ledger_secrets;

    EncryptedSharesMap compute_encrypted_shares(
      kv::Tx& tx, const LedgerSecretWrappingKey& ls_wrapping_key)
    {
      EncryptedSharesMap encrypted_shares;
      auto shares = ls_wrapping_key.get_shares();

      auto active_recovery_members_info =
        InternalTablesAccess::get_active_recovery_members(tx);

      size_t share_index = 0;
      for (auto const& [member_id, enc_pub_key] : active_recovery_members_info)
      {
        auto member_enc_pubk = crypto::make_rsa_public_key(enc_pub_key);
        auto raw_share = std::vector<uint8_t>(
          shares[share_index].begin(), shares[share_index].end());
        encrypted_shares[member_id] = member_enc_pubk->rsa_oaep_wrap(raw_share);
        OPENSSL_cleanse(raw_share.data(), raw_share.size());
        OPENSSL_cleanse(shares[share_index].data(), shares[share_index].size());
        share_index++;
      }

      return encrypted_shares;
    }

    void shuffle_recovery_shares(
      kv::Tx& tx, const LedgerSecretPtr& latest_ledger_secret)
    {
      auto active_recovery_members_info =
        InternalTablesAccess::get_active_recovery_members(tx);
      size_t recovery_threshold =
        InternalTablesAccess::get_recovery_threshold(tx);

      if (active_recovery_members_info.empty())
      {
        throw std::logic_error(
          "There should be at least one active recovery member to issue "
          "recovery shares");
      }

      if (recovery_threshold == 0)
      {
        throw std::logic_error(
          "Recovery threshold should be set before recovery "
          "shares are computed");
      }

      if (recovery_threshold > active_recovery_members_info.size())
      {
        throw std::logic_error(fmt::format(
          "Recovery threshold {} should be equal to or less than the number of "
          "active recovery members {}",
          recovery_threshold,
          active_recovery_members_info.size()));
      }

      const auto num_shares = active_recovery_members_info.size();
      auto ls_wrapping_key =
        LedgerSecretWrappingKey(num_shares, recovery_threshold);

      auto wrapped_latest_ls = ls_wrapping_key.wrap(latest_ledger_secret);
      auto recovery_shares = tx.rw<ccf::RecoveryShares>(Tables::SHARES);
      recovery_shares->put(
        {wrapped_latest_ls,
         compute_encrypted_shares(tx, ls_wrapping_key),
         latest_ledger_secret->previous_secret_stored_version});
    }

    void set_recovery_shares_info(
      kv::Tx& tx,
      const LedgerSecretPtr& latest_ledger_secret,
      const std::optional<VersionedLedgerSecret>& previous_ledger_secret =
        std::nullopt,
      std::optional<kv::Version> latest_ls_version = std::nullopt)
    {
      // First, generate a fresh ledger secrets wrapping key and wrap the
      // latest ledger secret with it. Then, encrypt the penultimate ledger
      // secret with the latest ledger secret and split the ledger secret
      // wrapping key, allocating a new share for each active recovery member.
      // Finally, encrypt each share with the public key of each member and
      // record it in the shares table.

      shuffle_recovery_shares(tx, latest_ledger_secret);

      auto encrypted_ls = tx.rw<ccf::EncryptedLedgerSecretsInfo>(
        Tables::ENCRYPTED_PAST_LEDGER_SECRET);

      std::vector<uint8_t> encrypted_previous_secret = {};
      kv::Version version_previous_secret = kv::NoVersion;
      if (previous_ledger_secret.has_value())
      {
        version_previous_secret = previous_ledger_secret->first;

        crypto::GcmCipher encrypted_previous_ls(
          previous_ledger_secret->second->raw_key.size());
        encrypted_previous_ls.hdr.set_random_iv();

        latest_ledger_secret->key->encrypt(
          encrypted_previous_ls.hdr.get_iv(),
          previous_ledger_secret->second->raw_key,
          {},
          encrypted_previous_ls.cipher,
          encrypted_previous_ls.hdr.tag);

        encrypted_previous_secret = encrypted_previous_ls.serialise();
        encrypted_ls->put(
          {PreviousLedgerSecretInfo(
             std::move(encrypted_previous_secret),
             version_previous_secret,
             encrypted_ls->get_version_of_previous_write()),
           latest_ls_version});
      }
      else
      {
        encrypted_ls->put({std::nullopt, latest_ls_version});
      }
    }

    std::vector<uint8_t> encrypt_submitted_share(
      const std::vector<uint8_t>& submitted_share,
      const LedgerSecretPtr& current_ledger_secret)
    {
      // Submitted recovery shares are encrypted with the latest ledger secret.
      crypto::GcmCipher encrypted_submitted_share(submitted_share.size());

      encrypted_submitted_share.hdr.set_random_iv();

      current_ledger_secret->key->encrypt(
        encrypted_submitted_share.hdr.get_iv(),
        submitted_share,
        {},
        encrypted_submitted_share.cipher,
        encrypted_submitted_share.hdr.tag);

      return encrypted_submitted_share.serialise();
    }

    std::vector<uint8_t> decrypt_submitted_share(
      const std::vector<uint8_t>& encrypted_submitted_share,
      LedgerSecretPtr&& current_ledger_secret)
    {
      crypto::GcmCipher encrypted_share;
      encrypted_share.deserialise(encrypted_submitted_share);
      std::vector<uint8_t> decrypted_share;

      current_ledger_secret->key->decrypt(
        encrypted_share.hdr.get_iv(),
        encrypted_share.hdr.tag,
        encrypted_share.cipher,
        {},
        decrypted_share);

      return decrypted_share;
    }

    LedgerSecretWrappingKey combine_from_encrypted_submitted_shares(kv::Tx& tx)
    {
      auto encrypted_submitted_shares = tx.rw<ccf::EncryptedSubmittedShares>(
        Tables::ENCRYPTED_SUBMITTED_SHARES);
      auto config = tx.rw<ccf::Configuration>(Tables::CONFIGURATION);

#ifdef NEW_SSS
      std::vector<crypto::Share> shares = {};
      encrypted_submitted_shares->foreach(
        [&shares, &tx, this](
          const MemberId, const EncryptedSubmittedShare& encrypted_share) {
          auto decrypted_share = decrypt_submitted_share(
            encrypted_share, ledger_secrets->get_latest(tx).second);
          shares.emplace_back(decrypted_share);
          LOG_INFO_FMT("YYY Share: {}", shares.back().to_str());
          OPENSSL_cleanse(decrypted_share.data(), decrypted_share.size());
          return true;
        });

      auto recovery_threshold = config->get()->recovery_threshold;
      if (recovery_threshold > shares.size())
      {
        throw std::logic_error(fmt::format(
          "Error combining recovery shares: only {} recovery shares were "
          "submitted but recovery threshold is {}",
          shares.size(),
          recovery_threshold));
      }

      return LedgerSecretWrappingKey(std::move(shares), recovery_threshold);
#else
      std::vector<SecretSharing::Share> shares = {};
      encrypted_submitted_shares->foreach(
        [&shares, &tx, this](
          const MemberId, const EncryptedSubmittedShare& encrypted_share) {
          SecretSharing::Share share;
          auto decrypted_share = decrypt_submitted_share(
            encrypted_share, ledger_secrets->get_latest(tx).second);
          std::copy_n(
            decrypted_share.begin(),
            SecretSharing::SHARE_LENGTH,
            share.begin());
          OPENSSL_cleanse(decrypted_share.data(), decrypted_share.size());
          shares.emplace_back(share);
          return true;
        });

      auto recovery_threshold = config->get()->recovery_threshold;
      if (recovery_threshold > shares.size())
      {
        throw std::logic_error(fmt::format(
          "Error combining recovery shares: only {} recovery shares were "
          "submitted but recovery threshold is {}",
          shares.size(),
          recovery_threshold));
      }

      return LedgerSecretWrappingKey(shares, recovery_threshold);
#endif
    }

  public:
    ShareManager(const std::shared_ptr<LedgerSecrets>& ledger_secrets_) :
      ledger_secrets(ledger_secrets_)
    {}

    /** Issue new recovery shares for the current ledger secret, recording the
     * wrapped new ledger secret and encrypted previous ledger secret in the
     * store.
     *
     * @param tx Store transaction object
     */
    void issue_recovery_shares(kv::Tx& tx)
    {
      auto [latest, penultimate] =
        ledger_secrets->get_latest_and_penultimate(tx);

      set_recovery_shares_info(tx, latest.second, penultimate, latest.first);
    }

    /** Issue new recovery shares of the new ledger secret, recording the
     * wrapped new ledger secret and encrypted current (now previous) ledger
     * secret in the store.
     *
     * @param tx Store transaction object
     * @param new_ledger_secret Pointer to new ledger secret
     *
     * Note: The version at which the new ledger secret is applicable from is
     * derived from the hook at which the ledger secret is applied to the
     * store.
     */
    void issue_recovery_shares(kv::Tx& tx, LedgerSecretPtr new_ledger_secret)
    {
      set_recovery_shares_info(
        tx, new_ledger_secret, ledger_secrets->get_latest(tx));
    }

    /** Issue new recovery shares of the same current ledger secret to all
     * active recovery members. The encrypted ledger secrets recorded in the
     * store are not updated.
     *
     * @param tx Store transaction object
     */
    void shuffle_recovery_shares(kv::Tx& tx)
    {
      shuffle_recovery_shares(tx, ledger_secrets->get_latest(tx).second);
    }

    static std::optional<EncryptedShare> get_encrypted_share(
      kv::Tx& tx, const MemberId& member_id)
    {
      auto recovery_shares_info =
        tx.rw<ccf::RecoveryShares>(Tables::SHARES)->get();
      if (!recovery_shares_info.has_value())
      {
        throw std::logic_error(
          "Failed to retrieve current recovery shares info");
      }

      auto search = recovery_shares_info->encrypted_shares.find(member_id);
      if (search == recovery_shares_info->encrypted_shares.end())
      {
        return std::nullopt;
      }

      return search->second;
    }

    LedgerSecretsMap restore_recovery_shares_info(
      kv::Tx& tx,
      const RecoveredEncryptedLedgerSecrets& recovery_ledger_secrets)
    {
      // First, re-assemble the ledger secret wrapping key from the submitted
      // encrypted shares. Then, unwrap the latest ledger secret and use it to
      // decrypt the sequence of recovered ledger secrets, from the last one.

      if (recovery_ledger_secrets.empty())
      {
        throw std::logic_error("No recovery ledger secrets");
      }

      auto recovery_shares_info =
        tx.ro<ccf::RecoveryShares>(Tables::SHARES)->get();
      if (!recovery_shares_info.has_value())
      {
        throw std::logic_error(
          "Failed to retrieve current recovery shares info");
      }

      auto restored_ls = combine_from_encrypted_submitted_shares(tx).unwrap(
        recovery_shares_info->wrapped_latest_ledger_secret);

      LOG_DEBUG_FMT(
        "Recovering {} encrypted ledger secrets",
        recovery_ledger_secrets.size());

      auto& current_ledger_secret_version =
        recovery_ledger_secrets.back().next_version;
      if (!current_ledger_secret_version.has_value())
      {
        // This should always be set by the recovery hook, which sets this to
        // the version at which it is called if unset in the store
        throw std::logic_error("Current ledger secret version should be set");
      }

      auto encrypted_previous_ledger_secret =
        tx.ro<ccf::EncryptedLedgerSecretsInfo>(
          Tables::ENCRYPTED_PAST_LEDGER_SECRET);

      LedgerSecretsMap restored_ledger_secrets = {};
      auto s = restored_ledger_secrets.emplace(
        current_ledger_secret_version.value(),
        std::make_shared<LedgerSecret>(
          std::move(restored_ls->raw_key),
          encrypted_previous_ledger_secret->get_version_of_previous_write()));
      auto latest_ls = s.first->second;

      for (auto it = recovery_ledger_secrets.rbegin();
           it != recovery_ledger_secrets.rend();
           it++)
      {
        if (!it->previous_ledger_secret.has_value())
        {
          // Very first entry does not encrypt any other ledger secret
          break;
        }

        auto decrypted_ls_raw = decrypt_previous_ledger_secret_raw(
          latest_ls, it->previous_ledger_secret->encrypted_data);

        auto secret = restored_ledger_secrets.emplace(
          it->previous_ledger_secret->version,
          std::make_shared<LedgerSecret>(
            std::move(decrypted_ls_raw),
            it->previous_ledger_secret->previous_secret_stored_version));
        latest_ls = secret.first->second;
      }

      return restored_ledger_secrets;
    }

    size_t submit_recovery_share(
      kv::Tx& tx,
      MemberId member_id,
      const std::vector<uint8_t>& submitted_recovery_share)
    {
      auto service = tx.rw<ccf::Service>(Tables::SERVICE);
      auto encrypted_submitted_shares = tx.rw<ccf::EncryptedSubmittedShares>(
        Tables::ENCRYPTED_SUBMITTED_SHARES);
      auto active_service = service->get();
      if (!active_service.has_value())
      {
        throw std::logic_error("Failed to get active service");
      }

      encrypted_submitted_shares->put(
        member_id,
        encrypt_submitted_share(
          submitted_recovery_share, ledger_secrets->get_latest(tx).second));

      return encrypted_submitted_shares->size();
    }

    static void clear_submitted_recovery_shares(kv::Tx& tx)
    {
      auto encrypted_submitted_shares = tx.rw<ccf::EncryptedSubmittedShares>(
        Tables::ENCRYPTED_SUBMITTED_SHARES);
      encrypted_submitted_shares->clear();
    }
  };
}