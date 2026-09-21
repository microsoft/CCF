// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "node/open_recovered_service.h"

#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/nodes.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"
#include "node/ledger_secrets.h"
#include "node/share_manager.h"
#include "service/tables/shares.h"
#include "service/tables/submitted_shares.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

namespace
{
  constexpr size_t certificate_validity_period_days = 365;
  using namespace std::literals;

  struct TestState
  {
    std::shared_ptr<ccf::kv::Store> store;
    std::shared_ptr<ccf::LedgerSecrets> ledger_secrets;
    std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> service_key;
    ccf::crypto::Pem service_cert;
  };

  // Builds a store in the state a recovering node reaches at the end of the
  // private ledger replay, just before it decides whether to open the service:
  // one active recovery member, a recovery threshold of 1, a submitted share
  // from that member, and the service in the given status (normally
  // WAITING_FOR_RECOVERY_SHARES).
  TestState make_recovering_state(ccf::ServiceStatus status)
  {
    TestState ts;
    ts.store = std::make_shared<ccf::kv::Store>();
    ts.store->set_consensus(std::make_shared<ccf::kv::test::StubConsensus>());
    ts.store->set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
    ts.store->initialise_term(2);

    ts.ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
    ts.ledger_secrets->init();

    ts.service_key = std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
      ccf::crypto::make_ec_key_pair());
    const auto valid_from =
      ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
    const auto valid_to = ccf::crypto::compute_cert_valid_to_string(
      valid_from, certificate_validity_period_days);
    ts.service_cert =
      ts.service_key->self_sign("CN=Test Service", valid_from, valid_to);

    auto tx = ts.store->create_tx();

    tx.rw<ccf::Configuration>(ccf::Tables::CONFIGURATION)->put({1});

    auto member_kp = ccf::crypto::make_ec_key_pair();
    auto member_cert = member_kp->self_sign("CN=member", valid_from, valid_to);
    const auto member_id =
      ccf::crypto::Sha256Hash(ccf::crypto::cert_pem_to_der(member_cert))
        .hex_str();
    tx.rw<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO)
      ->put(member_id, {ccf::MemberStatus::ACTIVE});
    tx.rw<ccf::MemberPublicEncryptionKeys>(
        ccf::Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS)
      ->put(member_id, ccf::crypto::make_rsa_key_pair()->public_key_pem());

    ccf::ServiceInfo service_info;
    service_info.cert = ts.service_cert;
    service_info.status = status;
    service_info.current_service_create_txid = ccf::TxID{2, 1};
    tx.rw<ccf::Service>(ccf::Tables::SERVICE)->put(service_info);

    // A submitted share, as left behind by the recovery share submission
    // which triggered the private ledger read.
    tx.rw<ccf::EncryptedSubmittedShares>(
        ccf::Tables::ENCRYPTED_SUBMITTED_SHARES)
      ->put(member_id, {1, 2, 3});

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    return ts;
  }
}

TEST_CASE("Opening a recovered service")
{
  auto ts =
    make_recovering_state(ccf::ServiceStatus::WAITING_FOR_RECOVERY_SHARES);
  ccf::ShareManager share_manager(ts.ledger_secrets);

  auto tx = ts.store->create_tx();
  ccf::open_recovered_service(tx, share_manager, *ts.service_key);
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

  auto ro = ts.store->create_read_only_tx();

  INFO("The service is open");
  const auto service = ro.ro<ccf::Service>(ccf::Tables::SERVICE)->get();
  REQUIRE(service.has_value());
  REQUIRE(service->status == ccf::ServiceStatus::OPEN);

  INFO("Submitted recovery shares were cleared");
  REQUIRE(
    ro.ro<ccf::EncryptedSubmittedShares>(
        ccf::Tables::ENCRYPTED_SUBMITTED_SHARES)
      ->size() == 0);

  INFO("Fresh recovery shares were issued for the new ledger secret");
  REQUIRE(ro.ro<ccf::EncryptedLedgerSecretsInfo>(
              ccf::Tables::ENCRYPTED_PAST_LEDGER_SECRET)
            ->has());
  REQUIRE(ro.ro<ccf::RecoveryShares>(ccf::Tables::SHARES)->has());

  INFO("The previous identity was endorsed by the new service key");
  const auto endorsement =
    ro.ro<ccf::PreviousServiceIdentityEndorsement>(
        ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
      ->get(ccf::IdentityType::CLASSICAL);
  REQUIRE(endorsement.has_value());
  REQUIRE(endorsement->endorsing_key == ts.service_key->public_key_der());
}

TEST_CASE("Opening a recovered service happens at most once")
{
  // If the service is no longer waiting for shares, another node has already
  // completed recovery: this node must refuse rather than open twice.
  for (const auto status :
       {ccf::ServiceStatus::OPEN,
        ccf::ServiceStatus::RECOVERING,
        ccf::ServiceStatus::OPENING})
  {
    CAPTURE(status);
    auto ts = make_recovering_state(status);
    ccf::ShareManager share_manager(ts.ledger_secrets);

    auto tx = ts.store->create_tx();
    REQUIRE_THROWS_AS(
      ccf::open_recovered_service(tx, share_manager, *ts.service_key),
      std::logic_error);
  }
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  return context.run();
}
