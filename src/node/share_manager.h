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

#include <nlohmann/json.hpp>
#include <vector>

namespace ccf
{
  class LedgerSecretsWrappingKey
  {
  private:
    static constexpr auto KZ_KEY_SIZE = crypto::GCM_SIZE_KEY;
    std::vector<uint8_t> data; // Referred to as "kz" in TR
    bool has_wrapped = false;

  public:
    LedgerSecretsWrappingKey() :
      data(tls::create_entropy()->random(KZ_KEY_SIZE))
    {}

    template <typename T>
    LedgerSecretsWrappingKey(T&& split_secret) :
      data(
        std::make_move_iterator(split_secret.begin()),
        std::make_move_iterator(split_secret.begin() + split_secret.size()))
    {}

    template <typename T>
    T get_raw_data()
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

      // auto serialised_ls = nlohmann::json::to_msgpack(ledger_secrets);
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

    LedgerSecret unwrap(const std::vector<uint8_t>& encrypted_ledger_secret)
    {
      crypto::GcmCipher encrypted_ls;
      encrypted_ls.deserialise(encrypted_ledger_secret);
      std::vector<uint8_t> decrypted_ls(encrypted_ls.cipher.size());

      if (!crypto::KeyAesGcm(data).decrypt(
            encrypted_ls.hdr.get_iv(), // iv is 0
            encrypted_ls.hdr.tag,
            encrypted_ls.cipher,
            nullb,
            decrypted_ls.data()))
      {
        throw std::logic_error("Decryption of ledger secrets failed");
      }

      return LedgerSecret(decrypted_ls);
    }
  };

  class ShareManager
  {
  private:
    NetworkState& network;

  public:
    ShareManager(NetworkState& network_) : network(network_) {}

    void update_key_share_info(Store::Tx& tx)
    {
      // TODO: Update this comment
      // First, generated a fresh ledger secrets wrapping key and wrap the
      // ledger secrets with it. Then, split the ledger secrets wrapping key,
      // allocating a new share for each active member. Finally, encrypt each
      // share with the public key of each member and record it in the KV.
      auto ls_wrapping_key = LedgerSecretsWrappingKey();
      // TODO:
      // 1. Wrap the latest ledger secret only
      auto encrypted_ls =
        ls_wrapping_key.wrap(network.ledger_secrets->get_latest());

      // 2. Encrypt the penultimate ledger secrets with the latest ledger
      // secrets
      std::vector<uint8_t> encrypted_penultimate_secrets = {};
      auto penultimate_ledger_secret =
        network.ledger_secrets->get_penultimate();
      if (penultimate_ledger_secret.has_value())
      {
        LOG_FAIL_FMT(
          "Encrypting penultimate ledger secrets with latest ledget secret");

        // TODO: Probably move this logic in the LedgerSecret class directly
        // (i.e. a LedgerSecret can now also encrypt)
        // Or each LedgerSecret knows about its predecessor and can encrypt it
        // if necessary (wait until the replay is done)

        crypto::GcmCipher encrypted_pls(
          penultimate_ledger_secret->master.size());

        crypto::KeyAesGcm(network.ledger_secrets->get_latest().master)
          .encrypt(
            tls::create_entropy()->random(crypto::GCM_SIZE_IV),
            penultimate_ledger_secret->master,
            nullb,
            encrypted_pls.cipher.data(),
            encrypted_pls.hdr.tag);

        encrypted_penultimate_secrets = encrypted_pls.serialise();
      }
      else
      {
        // TODO: Delete
        LOG_FAIL_FMT("No penultimate ledger secrets");
      }

      auto secret_to_split =
        ls_wrapping_key.get_raw_data<SecretSharing::SplitSecret>();

      GenesisGenerator g(network, tx);
      auto active_members_info = g.get_active_members_keyshare();

      size_t threshold = g.get_recovery_threshold();
      auto shares = SecretSharing::split(
        secret_to_split, active_members_info.size(), threshold);

      size_t share_index = 0;
      EncryptedSharesMap encrypted_shares;
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

      g.add_key_share_info(
        {encrypted_ls, encrypted_penultimate_secrets, encrypted_shares});
    }

    // For now, the shares are passed directly to this function. Shares should
    // be retrieved from the KV instead.
    std::vector<kv::Version> restore_key_share_info(
      Store::Tx& tx, const std::vector<SecretSharing::Share>& shares)
    {
      // TODO: Update this comment
      // First, re-assemble the ledger secrets wrapping key from the given
      // shares. Then, unwrap and restore the ledger secrets.
      auto ls_wrapping_key =
        LedgerSecretsWrappingKey(SecretSharing::combine(shares, shares.size()));

      auto shares_view = tx.get_view(network.shares);
      auto key_share_info = shares_view->get(0);
      if (!key_share_info.has_value())
      {
        throw std::logic_error("Failed to retrieve current key share info");
      }

      // TODO: Also decrypt the previous ledger secrets, as well as the rest of
      // the ledger secrets so far

      auto restored_ls =
        ls_wrapping_key.unwrap(key_share_info->encrypted_ledger_secret);

      // TODO: Very much hardcoded for now
      network.ledger_secrets->set_secret(1, restored_ls.master);

      return {1};
    }
  };
}