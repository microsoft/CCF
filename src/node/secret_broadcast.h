// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "genesis_gen.h"
#include "ledger_secrets.h"
#include "network_state.h"
#include "tls/key_exchange.h"

#include <optional>

namespace ccf
{
  class LedgerSecretsBroadcast
  {
  private:
    static std::vector<uint8_t> encrypt_ledger_secret(
      tls::KeyPairPtr encryption_key,
      tls::PublicKeyPtr backup_pubk,
      std::vector<uint8_t>&& plain)
    {
      // Encrypt secrets with a shared secret derived from backup public
      // key
      crypto::KeyAesGcm backup_shared_secret(
        tls::KeyExchangeContext(encryption_key, backup_pubk)
          .compute_shared_secret());

      crypto::GcmCipher gcmcipher(plain.size());
      auto iv = tls::create_entropy()->random(gcmcipher.hdr.get_iv().n);
      std::copy(iv.begin(), iv.end(), gcmcipher.hdr.iv);

      backup_shared_secret.encrypt(
        iv, plain, nullb, gcmcipher.cipher.data(), gcmcipher.hdr.tag);

      return gcmcipher.serialise();
    }

  public:
    // TODO: Pass version of previous secret here as well??!!
    static void broadcast_some(
      NetworkState& network,
      tls::KeyPairPtr encryption_key,
      NodeId self,
      kv::Tx& tx,
      const LedgerSecretsMap& some_ledger_secrets)
    {
      GenesisGenerator g(network, tx);
      auto secrets = tx.rw(network.secrets);

      auto trusted_nodes = g.get_trusted_nodes(self);

      for (auto [nid, ni] : trusted_nodes)
      {
        std::vector<EncryptedLedgerSecret> ledger_secrets_for_node;

        for (auto s : some_ledger_secrets)
        {
          ledger_secrets_for_node.push_back(
            {s.first,
             encrypt_ledger_secret(
               encryption_key,
               tls::make_public_key(ni.encryption_pub_key),
               std::move(s.second.raw_key))});
        }

        secrets->put(
          nid,
          {encryption_key->public_key_pem().raw(),
           std::move(ledger_secrets_for_node)});
      }
    }

    static void broadcast_new(
      NetworkState& network,
      tls::KeyPairPtr encryption_key,
      kv::Tx& tx,
      LedgerSecret&& new_ledger_secret)
    {
      GenesisGenerator g(network, tx);
      auto secrets = tx.rw(network.secrets);

      for (auto [nid, ni] : g.get_trusted_nodes())
      {
        std::vector<EncryptedLedgerSecret> ledger_secrets_for_node;
        ledger_secrets_for_node.push_back(
          {std::nullopt,
           encrypt_ledger_secret(
             encryption_key,
             tls::make_public_key(ni.encryption_pub_key),
             std::move(new_ledger_secret.raw_key)),
           new_ledger_secret.previous_secret_stored_version});

        secrets->put(
          nid,
          {encryption_key->public_key_pem().raw(),
           std::move(ledger_secrets_for_node)});
      }
    }

    static std::vector<uint8_t> decrypt(
      tls::KeyPairPtr encryption_key,
      tls::PublicKeyPtr primary_pubk,
      const std::vector<uint8_t>& cipher)
    {
      crypto::GcmCipher gcmcipher;
      gcmcipher.deserialise(cipher);
      std::vector<uint8_t> plain(gcmcipher.cipher.size());

      crypto::KeyAesGcm primary_shared_key(
        tls::KeyExchangeContext(encryption_key, primary_pubk)
          .compute_shared_secret());

      if (!primary_shared_key.decrypt(
            gcmcipher.hdr.get_iv(),
            gcmcipher.hdr.tag,
            gcmcipher.cipher,
            nullb,
            plain.data()))
      {
        throw std::logic_error("Decryption of ledger secret failed");
      }

      return plain;
    }
  };
}