// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "genesis_gen.h"
#include "kv/encryptor.h"
#include "ledger_secrets.h"
#include "network_state.h"
#include "secret_share.h"
#include "tls/entropy.h"
#include "tls/rsa_key_pair.h"

#include <vector>

namespace ccf
{
  class LedgerSecretWrappingKey
  {
  private:
    static constexpr auto KZ_KEY_SIZE = crypto::GCM_SIZE_KEY;
    std::vector<uint8_t> data; // Referred to as "kz" in TR
    bool has_wrapped = false;

  public:
    LedgerSecretWrappingKey() : data(tls::create_entropy()->random(KZ_KEY_SIZE))
    {}

    template <typename T>
    LedgerSecretWrappingKey(T&& split_secret) :
      data(
        std::make_move_iterator(split_secret.begin()),
        std::make_move_iterator(split_secret.begin() + split_secret.size()))
    {}

    template <typename T>
    T get_raw_data() const
    {
      T ret;
      std::copy_n(data.begin(), data.size(), ret.begin());
      return ret;
    }

    std::vector<uint8_t> wrap(const LedgerSecret& ledger_secret)
    {
      if (has_wrapped)
      {
        throw std::logic_error(
          "Ledger Secret wrapping key has already wrapped once");
      }

      crypto::GcmCipher encrypted_ls(ledger_secret.raw_key.size());

      crypto::KeyAesGcm(data).encrypt(
        encrypted_ls.hdr.get_iv(), // iv is always 0 here as the share wrapping
                                   // key is never re-used for encryption
        ledger_secret.raw_key,
        nullb,
        encrypted_ls.cipher.data(),
        encrypted_ls.hdr.tag);

      has_wrapped = true;

      return encrypted_ls.serialise();
    }

    LedgerSecret unwrap(
      const std::vector<uint8_t>& wrapped_latest_ledger_secret)
    {
      crypto::GcmCipher encrypted_ls;
      encrypted_ls.deserialise(wrapped_latest_ledger_secret);
      std::vector<uint8_t> decrypted_ls(encrypted_ls.cipher.size());

      if (!crypto::KeyAesGcm(data).decrypt(
            encrypted_ls.hdr.get_iv(),
            encrypted_ls.hdr.tag,
            encrypted_ls.cipher,
            nullb,
            decrypted_ls.data()))
      {
        throw std::logic_error("Unwrapping latest ledger secret failed");
      }

      return LedgerSecret(std::move(decrypted_ls));
    }
  };

  // During recovery, a list of RecoveredEncryptedLedgerSecrets is constructed
  // from the local hook on the encrypted ledger secrets table. The key for each
  // entry is the version at which the next ledger secret is applicable from.
  using RecoveredEncryptedLedgerSecrets =
    std::map<kv::Version, std::optional<PreviousLedgerSecretInfo>>;

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
    NetworkState& network;

    EncryptedSharesMap compute_encrypted_shares(
      kv::Tx& tx, const LedgerSecretWrappingKey& ls_wrapping_key)
    {
      EncryptedSharesMap encrypted_shares;

      auto secret_to_split =
        ls_wrapping_key.get_raw_data<SecretSharing::SplitSecret>();

      GenesisGenerator g(network, tx);
      auto active_recovery_members_info = g.get_active_recovery_members();
      size_t recovery_threshold = g.get_recovery_threshold();

      if (active_recovery_members_info.size() == 0)
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

      auto shares = SecretSharing::split(
        secret_to_split,
        active_recovery_members_info.size(),
        recovery_threshold);

      size_t share_index = 0;
      for (auto const& [member_id, enc_pub_key] : active_recovery_members_info)
      {
        auto member_enc_pubk = tls::make_rsa_public_key(enc_pub_key);
        auto raw_share = std::vector<uint8_t>(
          shares[share_index].begin(), shares[share_index].end());
        encrypted_shares[member_id] = member_enc_pubk->wrap(raw_share);
        share_index++;
      }

      return encrypted_shares;
    }

    void shuffle_recovery_shares(
      kv::Tx& tx, const LedgerSecret& latest_ledger_secret)
    {
      auto ls_wrapping_key = LedgerSecretWrappingKey();
      auto wrapped_latest_ls = ls_wrapping_key.wrap(latest_ledger_secret);
      auto recovery_shares = tx.rw(network.shares);
      recovery_shares->put(
        0, {wrapped_latest_ls, compute_encrypted_shares(tx, ls_wrapping_key)});
    }

    void set_recovery_shares_info(
      kv::Tx& tx,
      const LedgerSecret& latest_ledger_secret,
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

      auto encrypted_ls = tx.rw(network.encrypted_ledger_secrets);

      std::vector<uint8_t> encrypted_previous_secret = {};
      kv::Version version_previous_secret = kv::NoVersion;
      if (previous_ledger_secret.has_value())
      {
        version_previous_secret = previous_ledger_secret->first;

        crypto::GcmCipher encrypted_previous_ls(
          previous_ledger_secret->second.raw_key.size());
        auto iv = tls::create_entropy()->random(crypto::GCM_SIZE_IV);
        encrypted_previous_ls.hdr.set_iv(iv.data(), iv.size());

        latest_ledger_secret.key->encrypt(
          encrypted_previous_ls.hdr.get_iv(),
          previous_ledger_secret->second.raw_key,
          nullb,
          encrypted_previous_ls.cipher.data(),
          encrypted_previous_ls.hdr.tag);

        encrypted_previous_secret = encrypted_previous_ls.serialise();

        LOG_FAIL_FMT(
          "Setting recovery share info with previous secret at "
          "{}",
          version_previous_secret);
        encrypted_ls->put(
          0,
          {PreviousLedgerSecretInfo(
             std::move(encrypted_previous_secret),
             version_previous_secret,
             std::nullopt),
           latest_ls_version});
      }
      else
      {
        LOG_FAIL_FMT("Setting recovery share info with no previous secret");
        encrypted_ls->put(0, {std::nullopt, latest_ls_version});
      }
    }

    std::vector<uint8_t> encrypt_submitted_share(
      const std::vector<uint8_t>& submitted_share,
      LedgerSecret&& current_ledger_secret)
    {
      // Submitted recovery shares are encrypted with the latest ledger secret.
      crypto::GcmCipher encrypted_submitted_share(submitted_share.size());

      auto iv = tls::create_entropy()->random(crypto::GCM_SIZE_IV);
      encrypted_submitted_share.hdr.set_iv(iv.data(), iv.size());

      current_ledger_secret.key->encrypt(
        encrypted_submitted_share.hdr.get_iv(),
        submitted_share,
        nullb,
        encrypted_submitted_share.cipher.data(),
        encrypted_submitted_share.hdr.tag);

      return encrypted_submitted_share.serialise();
    }

    std::vector<uint8_t> decrypt_submitted_share(
      const std::vector<uint8_t>& encrypted_submitted_share,
      LedgerSecret&& current_ledger_secret)
    {
      crypto::GcmCipher encrypted_share;
      encrypted_share.deserialise(encrypted_submitted_share);
      std::vector<uint8_t> decrypted_share(encrypted_share.cipher.size());

      current_ledger_secret.key->decrypt(
        encrypted_share.hdr.get_iv(),
        encrypted_share.hdr.tag,
        encrypted_share.cipher,
        nullb,
        decrypted_share.data());

      return decrypted_share;
    }

    LedgerSecretWrappingKey combine_from_submitted_shares(kv::Tx& tx)
    {
      auto submitted_shares = tx.rw(network.submitted_shares);
      auto config = tx.rw(network.config);

      std::vector<SecretSharing::Share> shares;
      submitted_shares->foreach([&shares, &tx, this](
                                  const MemberId,
                                  const std::vector<uint8_t>& encrypted_share) {
        SecretSharing::Share share;
        auto decrypted_share = decrypt_submitted_share(
          encrypted_share, network.ledger_secrets->get_latest(tx).second);
        std::copy_n(
          decrypted_share.begin(), SecretSharing::SHARE_LENGTH, share.begin());
        shares.emplace_back(share);
        return true;
      });

      auto recovery_threshold = config->get(0)->recovery_threshold;
      if (recovery_threshold > shares.size())
      {
        throw std::logic_error(fmt::format(
          "Error combining recovery shares: only {} recovery shares were "
          "submitted but recovery threshold is {}",
          shares.size(),
          recovery_threshold));
      }

      return LedgerSecretWrappingKey(
        SecretSharing::combine(shares, shares.size()));
    }

  public:
    ShareManager(NetworkState& network_) : network(network_) {}

    void issue_recovery_shares(kv::Tx& tx)
    {
      // Issue new recovery shares for the current ledger secret, recording the
      // wrapped new ledger secret and encrypted previous ledger secret in the
      // store.
      auto [latest, penultimate] =
        network.ledger_secrets->get_latest_and_penultimate(tx);

      set_recovery_shares_info(tx, latest.second, penultimate, latest.first);
    }

    void issue_recovery_shares(
      kv::Tx& tx, const LedgerSecret& new_ledger_secret)
    {
      // Issue new recovery shares of the new ledger secret, recording the
      // wrapped new ledger secret and encrypted previous ledger secret in the
      // store.
      // Note: The version at which the new ledger secret is applicable from is
      // derived from the hook at which the ledgersecret is applied to the
      // store.
      set_recovery_shares_info(
        tx, new_ledger_secret, network.ledger_secrets->get_latest(tx));
    }

    void reshuffle_recovery_shares(kv::Tx& tx)
    {
      // Issue new recovery shares of the _same_ current ledger secret to all
      // active recovery members. The encrypted ledger secrets recorded in the
      // store are _not_ updated.
      LOG_FAIL_FMT("Shuffling recovery shares");
      shuffle_recovery_shares(
        tx, network.ledger_secrets->get_latest(tx).second);
    }

    std::optional<EncryptedShare> get_encrypted_share(
      kv::Tx& tx, MemberId member_id)
    {
      auto recovery_shares_info = tx.rw(network.shares)->get(0);
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

    // TODO: rvalue recovery_ledger_secrets
    LedgerSecretsMap restore_recovery_shares_info(
      kv::Tx& tx,
      const RecoveredEncryptedLedgerSecrets& recovery_ledger_secrets)
    {
      // First, re-assemble the ledger secret wrapping key from the submitted
      // encrypted shares. Then, unwrap the latest ledger secret and use it to
      // decrypt the previous ledger secret and so on.

      if (recovery_ledger_secrets.empty())
      {
        throw std::logic_error(
          "There should be at least one encrypted ledger secret to recover");
      }

      auto recovery_shares_info = tx.ro(network.shares)->get(0);
      if (!recovery_shares_info.has_value())
      {
        throw std::logic_error(
          "Failed to retrieve current recovery shares info");
      }

      LedgerSecretsMap restored_ledger_secrets;

      auto restored_ls = combine_from_submitted_shares(tx).unwrap(
        recovery_shares_info->wrapped_latest_ledger_secret);
      auto decryption_key = restored_ls.raw_key;

      LOG_FAIL_FMT(
        "Recovering {} encrypted ledger secrets",
        recovery_ledger_secrets.size());

      restored_ledger_secrets.emplace(
        recovery_ledger_secrets.rbegin()->first, std::move(restored_ls));

      LOG_FAIL_FMT("Emplaced");

      for (auto it = recovery_ledger_secrets.rbegin();
           it != recovery_ledger_secrets.rend();
           it++)
      {
        LOG_FAIL_FMT("First!");
        if (!it->second.has_value())
        {
          // Very first entry does not encrypt any other ledger secret
          LOG_FAIL_FMT("Skipping!"); // TODO: Remove
          break;
        }

        crypto::GcmCipher encrypted_ls;
        encrypted_ls.deserialise(it->second->encrypted_data);
        std::vector<uint8_t> decrypted_ls(encrypted_ls.cipher.size());

        if (!crypto::KeyAesGcm(decryption_key)
               .decrypt(
                 encrypted_ls.hdr.get_iv(),
                 encrypted_ls.hdr.tag,
                 encrypted_ls.cipher,
                 nullb,
                 decrypted_ls.data()))
        {
          throw std::logic_error(fmt::format(
            "Decryption of ledger secret at {} failed", it->second->version));
        }

        LOG_FAIL_FMT("Recovering ledger secret at {}", it->second->version);
        decryption_key = decrypted_ls;
        restored_ledger_secrets.emplace(
          it->second->version, std::move(decrypted_ls));
        // if (std::next(it) == recovery_ledger_secrets.rend())
        // {
        //   restored_ledger_secrets.emplace(it->      ,
        //   std::move(decrypted_ls));
        // }
        // else
        // {
        //   restored_ledger_secrets.emplace(
        //     std::next(it)->first, std::move(decrypted_ls));
        // }
      }

      // recovery_ledger_secrets.clear();

      return restored_ledger_secrets;
    }

    size_t submit_recovery_share(
      kv::Tx& tx,
      MemberId member_id,
      const std::vector<uint8_t>& submitted_recovery_share)
    {
      auto service = tx.rw(network.service);
      auto submitted_shares = tx.rw(network.submitted_shares);
      auto active_service = service->get(0);
      if (!active_service.has_value())
      {
        throw std::logic_error("Failed to get active service");
      }

      submitted_shares->put(
        member_id,
        encrypt_submitted_share(
          submitted_recovery_share,
          network.ledger_secrets->get_latest(tx).second));

      size_t submitted_shares_count = 0;
      submitted_shares->foreach(
        [&submitted_shares_count](const MemberId, const std::vector<uint8_t>&) {
          submitted_shares_count++;
          return true;
        });

      return submitted_shares_count;
    }

    void clear_submitted_recovery_shares(kv::Tx& tx)
    {
      auto submitted_shares = tx.rw(network.submitted_shares);

      std::vector<uint8_t> submitted_share_ids = {};

      submitted_shares->foreach(
        [&submitted_share_ids](
          const MemberId member_id, const std::vector<uint8_t>&) {
          submitted_share_ids.push_back(member_id);
          return true;
        });

      for (auto const& id : submitted_share_ids)
      {
        submitted_shares->remove(id);
      }
    }
  };
}