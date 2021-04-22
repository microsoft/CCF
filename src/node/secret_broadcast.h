// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/key_wrap.h"
#include "crypto/rsa_key_pair.h"
#include "genesis_gen.h"
#include "ledger_secrets.h"
#include "network_state.h"

#include <optional>

namespace ccf
{
  class LedgerSecretsBroadcast
  {
  public:
    static void broadcast_some(
      NetworkState& network,
      NodeId self,
      kv::Tx& tx,
      const LedgerSecretsMap& some_ledger_secrets)
    {
      GenesisGenerator g(network, tx);
      auto secrets = tx.rw(network.secrets);

      SecretsForNodes secrets_for_nodes;

      for (auto [nid, ni] : g.get_trusted_nodes(self))
      {
        std::vector<EncryptedLedgerSecret> ledger_secrets_for_node;

        for (auto s : some_ledger_secrets)
        {
          ledger_secrets_for_node.push_back(
            {s.first,
             crypto::ckm_rsa_pkcs_oaep_wrap(
               crypto::make_rsa_public_key(ni.encryption_pub_key),
               s.second->raw_key),
             s.second->previous_secret_stored_version});
        }

        secrets_for_nodes.emplace(nid, std::move(ledger_secrets_for_node));
      }

      secrets->put(0, {{}, secrets_for_nodes});
    }

    static void broadcast_new(
      NetworkState& network, kv::Tx& tx, LedgerSecretPtr&& new_ledger_secret)
    {
      GenesisGenerator g(network, tx);
      auto secrets = tx.rw(network.secrets);

      SecretsForNodes secrets_for_nodes;

      for (auto [nid, ni] : g.get_trusted_nodes())
      {
        std::vector<EncryptedLedgerSecret> ledger_secrets_for_node;

        LOG_FAIL_FMT(
          "Wrapping ledger secret: {}",
          tls::b64_from_raw(new_ledger_secret->raw_key));
        ledger_secrets_for_node.push_back(
          {std::nullopt,
           crypto::ckm_rsa_pkcs_oaep_wrap(
             crypto::make_rsa_public_key(ni.encryption_pub_key),
             new_ledger_secret->raw_key),
           new_ledger_secret->previous_secret_stored_version});

        secrets_for_nodes.emplace(nid, std::move(ledger_secrets_for_node));
      }

      secrets->put(0, {{}, secrets_for_nodes});
    }

    static std::vector<uint8_t> decrypt(
      const crypto::RSAKeyPairPtr& encryption_key,
      const std::vector<uint8_t>& cipher)
    {
      auto unwrapped = crypto::ckm_rsa_pkcs_oaep_unwrap(encryption_key, cipher);

      LOG_FAIL_FMT("Unwrapped: {}", tls::b64_from_raw(unwrapped));

      return unwrapped;
    }
  };
}