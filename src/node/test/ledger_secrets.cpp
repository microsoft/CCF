// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/test/null_encryptor.h"
#include "kv/store.h"
#include "node/ledger_secrets.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

TEST_CASE("Ledger secret KV dependency lock ordering")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

  ccf::LedgerSecrets ledger_secrets;
  ledger_secrets.init();

  {
    auto tx = store.create_read_only_tx();
    CHECK(ledger_secrets.get_latest(tx).first == 1);

    const auto [latest, penultimate] =
      ledger_secrets.get_latest_and_penultimate(tx);
    CHECK(latest.first == 1);
    CHECK_FALSE(penultimate.has_value());

    const auto all = ledger_secrets.get(tx);
    REQUIRE(all.size() == 1);
    CHECK(all.begin()->first == 1);
  }

  // Map hooks run while the map is locked, matching the rekey path.
  store.set_map_hook(
    ccf::Tables::ENCRYPTED_LEDGER_SECRETS,
    ccf::Secrets::wrap_map_hook(
      [&ledger_secrets](
        ccf::kv::Version version,
        const ccf::Secrets::Write&) -> ccf::kv::ConsensusHookPtr {
        ledger_secrets.set_secret(version + 1, ccf::make_ledger_secret());
        return nullptr;
      }));

  auto tx = store.create_tx();
  tx.rw<ccf::Secrets>(ccf::Tables::ENCRYPTED_LEDGER_SECRETS)
    ->put(ccf::LedgerSecretsForNodes{});
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
}