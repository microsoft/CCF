// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/cryptobox.h"
#include "crypto/symmkey.h"
#include "ds/logger.h"
#include "genesisgen.h"
#include "ledgersecrets.h"
#include "networkstate.h"
#include "secretshare.h"
#include "tls/25519.h"
#include "tls/entropy.h"

#include <vector>

namespace ccf
{
  struct LedgerSecretWrappingKey
  {
  private:
    static constexpr auto KZ_KEY_SIZE = crypto::GCM_SIZE_KEY;

  public:
    std::vector<uint8_t> data; // Referred to as "kz" in TR

    LedgerSecretWrappingKey() : data(tls::create_entropy()->random(KZ_KEY_SIZE))
    {}

    template <typename T>
    LedgerSecretWrappingKey(const T& split_secret) :
      data(
        std::make_move_iterator(split_secret.begin()),
        std::make_move_iterator(split_secret.begin() + split_secret.size()))
    {}
  };

  class ShareManager
  {
  private:
    NetworkState& network;

  public:
    ShareManager(NetworkState& network_) : network(network_) {}

    void create(Store::Tx& tx)
    {
      // First, generated a fresh ledger secrets wrapping key and encrypt the
      // current ledger secrets with it
      auto ls_wrapping_key = LedgerSecretWrappingKey();

      crypto::GcmCipher encrypted_ls(LedgerSecret::MASTER_KEY_SIZE);
      crypto::KeyAesGcm(ls_wrapping_key.data)
        .encrypt(
          encrypted_ls.hdr
            .get_iv(), // iv is always 0 here as the share wrapping
                       // key is never re-used for encryption
          network.ledger_secrets->get_secret(1)->master,
          nullb,
          encrypted_ls.cipher.data(),
          encrypted_ls.hdr.tag);

      // Then, split the ledger secrets wrapping key, allocating a share to each
      // active member
      SecretSharing::SplitSecret secret_to_split = {};
      std::copy_n(
        ls_wrapping_key.data.begin(),
        ls_wrapping_key.data.size(),
        secret_to_split.begin());

      GenesisGenerator g(network, tx);
      auto active_members_info = g.get_active_members_keyshare();

      // For now, the secret sharing threshold is set to the number of initial
      // members
      size_t threshold = active_members_info.size();
      auto shares = SecretSharing::split(
        secret_to_split, active_members_info.size(), threshold);

      // Finally, encrypt each share with the public key of each member, using a
      // random nonce, and record in the KV
      EncryptedSharesMap encrypted_shares;
      auto nonce = tls::create_entropy()->random(crypto::Box::NONCE_SIZE);

      size_t share_index = 0;
      for (auto const& [member_id, enc_pub_key] : active_members_info)
      {
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

      g.add_key_share_info({encrypted_ls.serialise(), encrypted_shares});
    }

    // For now, the shares are passed directly to this function. Shares should
    // be retrieved from the KV instead.
    LedgerSecret restore(
      Store::Tx& tx, const std::vector<SecretSharing::Share>& shares)
    {
      // First, re-assemble the ledger secrets wrapping key from the given
      // shares
      auto ls_wrapping_key =
        LedgerSecretWrappingKey(SecretSharing::combine(shares, shares.size()));

      // Then, decrypt the ledger secrets
      auto shares_view = tx.get_view(network.shares);
      auto key_share_info = shares_view->get(0);
      if (!key_share_info.has_value())
      {
        throw std::logic_error("Failed to retrieve current key share info");
      }

      std::vector<uint8_t> decrypted_ls(LedgerSecret::MASTER_KEY_SIZE);
      crypto::GcmCipher encrypted_ls;
      encrypted_ls.deserialise(key_share_info->encrypted_ledger_secret);

      if (!crypto::KeyAesGcm(ls_wrapping_key.data)
             .decrypt(
               encrypted_ls.hdr.get_iv(), // iv is 0
               encrypted_ls.hdr.tag,
               encrypted_ls.cipher,
               nullb,
               decrypted_ls.data()))
      {
        throw std::logic_error("Decryption of ledger secrets failed");
      }

      return LedgerSecret(std::move(decrypted_ls));
    }
  };
}