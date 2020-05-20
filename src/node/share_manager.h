// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/crypto_box.h"
#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "genesis_gen.h"
#include "ledger_secrets.h"
#include "network_state.h"
#include "secret_share.h"
#include "tls/25519.h"
#include "tls/entropy.h"

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

      crypto::GcmCipher encrypted_ls(ledger_secret.master.size());

      crypto::KeyAesGcm(data).encrypt(
        encrypted_ls.hdr.get_iv(), // iv is always 0 here as the share wrapping
                                   // key is never re-used for encryption
        ledger_secret.master,
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

      return LedgerSecret(decrypted_ls);
    }
  };

  // During recovery, a list of RecoveredLedgerSecret is constructed from a
  // local hook.
  struct RecoveredLedgerSecret
  {
    // Version at which the next ledger secret is applicable from
    kv::Version next_version;

    // Previous ledger secret, encrypted with the current ledger secret
    std::vector<uint8_t> encrypted_ledger_secret;
  };

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
      auto active_members_info = g.get_active_members_keyshare();
      size_t recovery_threshold = g.get_recovery_threshold();

      auto shares = SecretSharing::split(
        secret_to_split, active_members_info.size(), recovery_threshold);

      size_t share_index = 0;
      for (auto const& [member_id, enc_pub_key] : active_members_info)
      {
        auto nonce = tls::create_entropy()->random(crypto::Box::NONCE_SIZE);
        auto share_raw = std::vector<uint8_t>(
          shares[share_index].begin(), shares[share_index].end());

        auto enc_pub_key_raw = tls::PublicX25519::parse(tls::Pem(enc_pub_key));
        auto encrypted_share = crypto::Box::create(
          share_raw,
          nonce,
          enc_pub_key_raw,
          network.encryption_key->private_raw);

        encrypted_shares[member_id] = {nonce, encrypted_share};
        share_index++;
      }

      return encrypted_shares;
    }

    void set_recovery_shares_info(
      kv::Tx& tx,
      const LedgerSecret& latest_ledger_secret,
      const std::optional<LedgerSecret>& previous_ledger_secret = std::nullopt,
      kv::Version latest_ls_version = kv::NoVersion)
    {
      // First, generate a fresh ledger secrets wrapping key and wrap the
      // latest ledger secret with it. Then, encrypt the penultimate ledger
      // secret with the latest ledger secret and split the ledger secret
      // wrapping key, allocating a new share for each active member. Finally,
      // encrypt each share with the public key of each member and record it in
      // the shares table.

      auto ls_wrapping_key = LedgerSecretWrappingKey();
      auto wrapped_latest_ls = ls_wrapping_key.wrap(latest_ledger_secret);

      std::vector<uint8_t> encrypted_previous_secret = {};
      if (previous_ledger_secret.has_value())
      {
        crypto::GcmCipher encrypted_previous_ls(
          previous_ledger_secret->master.size());
        auto iv = tls::create_entropy()->random(crypto::GCM_SIZE_IV);
        encrypted_previous_ls.hdr.set_iv(iv.data(), iv.size());

        crypto::KeyAesGcm(latest_ledger_secret.master)
          .encrypt(
            encrypted_previous_ls.hdr.get_iv(),
            previous_ledger_secret->master,
            nullb,
            encrypted_previous_ls.cipher.data(),
            encrypted_previous_ls.hdr.tag);

        encrypted_previous_secret = encrypted_previous_ls.serialise();
      }

      GenesisGenerator g(network, tx);
      g.add_key_share_info({{latest_ls_version, wrapped_latest_ls},
                            encrypted_previous_secret,
                            compute_encrypted_shares(tx, ls_wrapping_key)});
    }

  public:
    ShareManager(NetworkState& network_) : network(network_) {}

    void issue_shares(kv::Tx& tx)
    {
      // Assumes that the ledger secrets have not been updated since the
      // last time shares have been issued (i.e. genesis or re-sharing only)
      set_recovery_shares_info(tx, network.ledger_secrets->get_latest());
    }

    void issue_shares_on_recovery(kv::Tx& tx, kv::Version latest_ls_version)
    {
      set_recovery_shares_info(
        tx,
        network.ledger_secrets->get_latest(),
        network.ledger_secrets->get_penultimate(),
        latest_ls_version);
    }

    void issue_shares_on_rekey(
      kv::Tx& tx, const LedgerSecret& new_ledger_secret)
    {
      set_recovery_shares_info(
        tx, new_ledger_secret, network.ledger_secrets->get_latest());
    }

    // For now, the shares are passed directly to this function. Shares should
    // be retrieved from the KV instead.
    std::vector<kv::Version> restore_recovery_shares_info(
      kv::Tx& tx,
      const std::vector<SecretSharing::Share>& shares,
      const std::list<RecoveredLedgerSecret>& encrypted_recovery_secrets)
    {
      // First, re-assemble the ledger secret wrapping key from the given
      // shares. Then, unwrap the latest ledger secret and use it to decrypt the
      // previous ledger secret and so on.
      auto ls_wrapping_key =
        LedgerSecretWrappingKey(SecretSharing::combine(shares, shares.size()));

      auto recovery_shares_info = tx.get_view(network.shares)->get(0);
      if (!recovery_shares_info.has_value())
      {
        throw std::logic_error(
          "Failed to retrieve current recovery shares info");
      }

      std::list<LedgerSecrets::VersionedLedgerSecret> restored_ledger_secrets;

      // For now, we keep track of the restored versions so that the recovered
      // ledger secrets can be broadcast to backups
      std::vector<kv::Version> restored_versions;
      restored_versions.push_back(
        encrypted_recovery_secrets.back().next_version);

      auto restored_ls = ls_wrapping_key.unwrap(
        recovery_shares_info->wrapped_latest_ledger_secret.encrypted_data);

      restored_ledger_secrets.push_back(
        {encrypted_recovery_secrets.back().next_version, restored_ls});

      auto decryption_key = restored_ls.master;
      for (auto i = encrypted_recovery_secrets.rbegin();
           i != encrypted_recovery_secrets.rend();
           i++)
      {
        if (i->encrypted_ledger_secret.size() == 0)
        {
          // First entry does not encrypt any other ledger secret (i.e. genesis)
          break;
        }

        crypto::GcmCipher encrypted_ls;
        encrypted_ls.deserialise(i->encrypted_ledger_secret);
        auto decrypted_ls = std::vector<uint8_t>(encrypted_ls.cipher.size());

        if (!crypto::KeyAesGcm(decryption_key)
               .decrypt(
                 encrypted_ls.hdr.get_iv(),
                 encrypted_ls.hdr.tag,
                 encrypted_ls.cipher,
                 nullb,
                 decrypted_ls.data()))
        {
          throw std::logic_error(fmt::format(
            "Decryption of ledger secret at {} failed",
            std::next(i)->next_version));
        }

        restored_ledger_secrets.push_back(
          {std::next(i)->next_version, LedgerSecret(decrypted_ls)});

        restored_versions.push_back(std::next(i)->next_version);
        decryption_key = decrypted_ls;
      }

      restored_ledger_secrets.reverse();
      network.ledger_secrets->restore(std::move(restored_ledger_secrets));

      return restored_versions;
    }
  };
}