// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/service.h"
#include "crypto/certs.h"
#include "service/tables/config.h"
#include "service/tables/signatures.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "kv/null_encryptor.h"
#include "kv/store.h"
#include "node/hooks.h"
#include "node/internal_tables_access.h"

#include <algorithm>
#include <doctest/doctest.h>

using namespace ccf;

namespace
{
  struct TestIdentity
  {
    std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> key =
      std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
        ccf::crypto::make_ec_key_pair());
    ccf::crypto::Pem cert;

    TestIdentity()
    {
      REQUIRE(key != nullptr);
      // These tests parse certificates and extract keys, not check validity.
      // Deliberately expired dates avoid a future expiry deadline.
      cert = key->self_sign("CN=test", "20200101000000Z", "20201231235959Z");
    }
  };

  class TestConsensus : public ccf::kv::ConfigurableConsensus
  {
  public:
    ccf::kv::Configuration::Nodes configuration;
    ccf::SeqNo configuration_version = 0;
    size_t configuration_changes = 0;

    TestConsensus(ccf::kv::Configuration::Nodes configuration_) :
      configuration(std::move(configuration_))
    {}

    void add_configuration(
      ccf::SeqNo seqno,
      const ccf::kv::Configuration::Nodes& new_configuration) override
    {
      configuration_version = seqno;
      configuration = new_configuration;
      ++configuration_changes;
    }

    ccf::kv::Configuration::Nodes get_latest_configuration() override
    {
      return configuration;
    }

    ccf::kv::Configuration::Nodes get_latest_configuration_unsafe()
      const override
    {
      return configuration;
    }

    ccf::kv::ConsensusDetails get_details() override
    {
      return {};
    }
  };

  pal::snp::TcbVersionPolicy tcb_from_hex(
    pal::snp::ProductName product, const std::string& tcb_hex)
  {
    return pal::snp::TcbVersionRaw::from_hex(tcb_hex).to_policy(product);
  }

  void set_min_tcb_version(
    ccf::kv::Store& kv_store,
    const std::string& cpuid,
    const pal::snp::TcbVersionPolicy& tcb_version)
  {
    auto tx = kv_store.create_tx();
    tx.wo<SnpTcbVersionMap>(Tables::SNP_TCB_VERSIONS)->put(cpuid, tcb_version);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  void trust_tcb_version(
    ccf::kv::Store& kv_store,
    const std::string& cpuid,
    const pal::snp::TcbVersionPolicy& tcb_version,
    bool recovering)
  {
    auto tx = kv_store.create_tx();
    InternalTablesAccess::trust_node_snp_tcb_version(
      tx, cpuid, tcb_version, recovering);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Returns the minimum TCB version for the CPUID as JSON, to compare all its
  // fields, and the version at which it was last written
  std::pair<nlohmann::json, ccf::kv::Version> get_min_tcb_version(
    ccf::kv::Store& kv_store, const std::string& cpuid)
  {
    auto tx = kv_store.create_read_only_tx();
    auto* handle = tx.ro<SnpTcbVersionMap>(Tables::SNP_TCB_VERSIONS);
    const auto tcb_version = handle->get(cpuid);
    REQUIRE(tcb_version.has_value());
    const auto version = handle->get_version_of_previous_write(cpuid);
    REQUIRE(version.has_value());
    return {nlohmann::json(tcb_version.value()), version.value()};
  }
}

TEST_CASE("Adding a member does not populate an ACK")
{
  ccf::kv::Store kv_store;
  auto tx = kv_store.create_tx();

  const auto key_pair = ccf::crypto::make_ec_key_pair();
  const auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now());
  const auto cert = ccf::crypto::create_self_signed_cert(
    key_pair, "CN=member", {}, valid_from, 1);

  const auto member_id = InternalTablesAccess::add_member(tx, {cert});

  REQUIRE(
    tx.ro<ccf::MemberInfo>(Tables::MEMBER_INFO)->get(member_id).has_value());
  REQUIRE_FALSE(
    tx.ro<ccf::MemberAcks>(Tables::MEMBER_ACKS)->get(member_id).has_value());
}

TEST_CASE("Member admission and activation preserve recovery roles")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  const auto encryption_key =
    ccf::crypto::make_rsa_key_pair()->public_key_pem();
  NewMember member{identity.cert, std::nullopt, {{"name", "member"}}};

  SUBCASE("No recovery role or encryption key") {}
  SUBCASE("Explicit non-participant")
  {
    member.recovery_role = MemberRecoveryRole::NonParticipant;
  }
  SUBCASE("Legacy participant")
  {
    member.encryption_pub_key = encryption_key;
  }
  SUBCASE("Explicit participant")
  {
    member.encryption_pub_key = encryption_key;
    member.recovery_role = MemberRecoveryRole::Participant;
  }
  SUBCASE("Owner")
  {
    member.encryption_pub_key = encryption_key;
    member.recovery_role = MemberRecoveryRole::Owner;
  }

  const MemberId expected_id =
    ccf::crypto::Sha256Hash(ccf::crypto::cert_pem_to_der(identity.cert))
      .hex_str();
  auto tx = store.create_tx();
  REQUIRE(InternalTablesAccess::add_member(tx, member) == expected_id);
  auto* info = tx.ro<MemberInfo>(Tables::MEMBER_INFO);
  REQUIRE(
    info->get(expected_id) ==
    MemberDetails{
      MemberStatus::ACCEPTED, member.member_data, member.recovery_role});
  REQUIRE(InternalTablesAccess::get_active_recovery_participants(tx).empty());
  REQUIRE(InternalTablesAccess::get_active_recovery_owners(tx).empty());
  REQUIRE(
    InternalTablesAccess::is_recovery_participant_or_owner(tx, expected_id) ==
    member.encryption_pub_key.has_value());

  REQUIRE(InternalTablesAccess::activate_member(tx, expected_id));
  REQUIRE_FALSE(InternalTablesAccess::activate_member(tx, expected_id));
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

  auto ro = store.create_read_only_tx();
  REQUIRE(
    ro.ro<MemberInfo>(Tables::MEMBER_INFO)->get(expected_id) ==
    MemberDetails{
      MemberStatus::ACTIVE, member.member_data, member.recovery_role});
  REQUIRE(
    ro.ro<MemberCerts>(Tables::MEMBER_CERTS)->get(expected_id) ==
    identity.cert);
  REQUIRE(
    ro.ro<MemberPublicEncryptionKeys>(Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS)
      ->get(expected_id) == member.encryption_pub_key);
  std::map<MemberId, ccf::crypto::Pem> participants;
  std::map<MemberId, ccf::crypto::Pem> owners;
  if (member.encryption_pub_key.has_value())
  {
    if (member.recovery_role == MemberRecoveryRole::Owner)
    {
      owners.emplace(expected_id, encryption_key);
    }
    else
    {
      participants.emplace(expected_id, encryption_key);
    }
  }
  REQUIRE(
    InternalTablesAccess::get_active_recovery_participants(ro) == participants);
  REQUIRE(InternalTablesAccess::get_active_recovery_owners(ro) == owners);
}

TEST_CASE("Inconsistent member recovery roles are rejected before writing")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  const MemberId member_id =
    ccf::crypto::Sha256Hash(ccf::crypto::cert_pem_to_der(identity.cert))
      .hex_str();
  NewMember member{identity.cert};
  auto expected_error = fmt::format(
    "Member {} cannot be added as recovery_role has a value set but no "
    "encryption public key is specified",
    member_id.value());
  SUBCASE("Participant without an encryption key")
  {
    member.recovery_role = MemberRecoveryRole::Participant;
  }
  SUBCASE("Owner without an encryption key")
  {
    member.recovery_role = MemberRecoveryRole::Owner;
  }
  SUBCASE("Non-participant with an encryption key")
  {
    member.recovery_role = MemberRecoveryRole::NonParticipant;
    member.encryption_pub_key =
      ccf::crypto::make_rsa_key_pair()->public_key_pem();
    expected_error = fmt::format(
      "Recovery member {} cannot be added as with recovery role value of {}",
      member_id.value(),
      MemberRecoveryRole::NonParticipant);
  }

  const auto before = store.current_txid();
  auto tx = store.create_tx();
  REQUIRE_THROWS_WITH_AS(
    InternalTablesAccess::add_member(tx, member),
    expected_error.c_str(),
    std::logic_error);
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(store.current_txid() == before);
  auto ro = store.create_read_only_tx();
  REQUIRE(ro.ro<MemberCerts>(Tables::MEMBER_CERTS)->size() == 0);
  REQUIRE(ro.ro<MemberInfo>(Tables::MEMBER_INFO)->size() == 0);
  REQUIRE(
    ro.ro<MemberPublicEncryptionKeys>(Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS)
      ->size() == 0);
}

TEST_CASE("Adding an existing member does not replace their active state")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  const auto encryption_key =
    ccf::crypto::make_rsa_key_pair()->public_key_pem();
  const nlohmann::json data = {{"name", "original"}};
  MemberId member_id;
  {
    auto tx = store.create_tx();
    member_id = InternalTablesAccess::add_member(
      tx, {identity.cert, encryption_key, data, MemberRecoveryRole::Owner});
    REQUIRE(InternalTablesAccess::activate_member(tx, member_id));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto before = store.current_txid();
  {
    auto tx = store.create_tx();
    REQUIRE(
      InternalTablesAccess::add_member(
        tx,
        {identity.cert,
         std::nullopt,
         {{"name", "replacement"}},
         MemberRecoveryRole::NonParticipant}) == member_id);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  REQUIRE(store.current_txid() == before);
  auto ro = store.create_read_only_tx();
  REQUIRE(
    ro.ro<MemberInfo>(Tables::MEMBER_INFO)->get(member_id) ==
    MemberDetails{MemberStatus::ACTIVE, data, MemberRecoveryRole::Owner});
  REQUIRE(
    ro.ro<MemberCerts>(Tables::MEMBER_CERTS)->get(member_id) == identity.cert);
  REQUIRE(
    ro.ro<MemberPublicEncryptionKeys>(Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS)
      ->get(member_id) == encryption_key);
}

TEST_CASE("Activating an unknown member does not create member state")
{
  ccf::kv::Store store;
  const MemberId unknown_id = std::string("unknown");
  const auto before = store.current_txid();
  auto tx = store.create_tx();
  REQUIRE_THROWS_WITH_AS(
    InternalTablesAccess::activate_member(tx, unknown_id),
    "Member m[unknown] cannot be activated as they do not exist",
    std::logic_error);
  REQUIRE_FALSE(
    InternalTablesAccess::is_recovery_participant_or_owner(tx, unknown_id));
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(store.current_txid() == before);
  auto ro = store.create_read_only_tx();
  REQUIRE(ro.ro<MemberInfo>(Tables::MEMBER_INFO)->size() == 0);
}

TEST_CASE("User admission rejects duplicates and removal preserves other users")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  const TestIdentity retained_identity;
  NewUser user{identity.cert};
  SUBCASE("Without user data") {}
  SUBCASE("With user data")
  {
    user.user_data = {{"role", "reader"}};
  }
  const UserId expected_id =
    ccf::crypto::Sha256Hash(ccf::crypto::cert_pem_to_der(identity.cert))
      .hex_str();
  UserId retained_id;
  {
    auto tx = store.create_tx();
    retained_id = InternalTablesAccess::add_user(
      tx, {retained_identity.cert, {{"role", "retained"}}});
    REQUIRE(InternalTablesAccess::add_user(tx, user) == expected_id);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  {
    auto ro = store.create_read_only_tx();
    REQUIRE(
      ro.ro<UserCerts>(Tables::USER_CERTS)->get(expected_id) == identity.cert);
    const auto info = ro.ro<UserInfo>(Tables::USER_INFO)->get(expected_id);
    REQUIRE(info.has_value() == !user.user_data.is_null());
    if (info.has_value())
    {
      REQUIRE(info->user_data == user.user_data);
    }
  }

  const auto before_duplicate = store.current_txid();
  {
    auto tx = store.create_tx();
    REQUIRE_THROWS_WITH_AS(
      InternalTablesAccess::add_user(
        tx, {identity.cert, {{"role", "replacement"}}}),
      fmt::format("Certificate already exists for user {}", expected_id.value())
        .c_str(),
      std::logic_error);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  REQUIRE(store.current_txid() == before_duplicate);
  {
    auto ro = store.create_read_only_tx();
    const auto info = ro.ro<UserInfo>(Tables::USER_INFO)->get(expected_id);
    REQUIRE(info.has_value() == !user.user_data.is_null());
    if (info.has_value())
    {
      REQUIRE(info->user_data == user.user_data);
    }
  }

  for (size_t attempt = 0; attempt < 2; ++attempt)
  {
    auto tx = store.create_tx();
    InternalTablesAccess::remove_user(tx, expected_id);
    InternalTablesAccess::remove_user(tx, std::string("unknown"));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    auto ro = store.create_read_only_tx();
    REQUIRE_FALSE(ro.ro<UserCerts>(Tables::USER_CERTS)->has(expected_id));
    REQUIRE_FALSE(ro.ro<UserInfo>(Tables::USER_INFO)->has(expected_id));
    REQUIRE(ro.ro<UserCerts>(Tables::USER_CERTS)->size() == 1);
    REQUIRE(ro.ro<UserInfo>(Tables::USER_INFO)->size() == 1);
    REQUIRE(
      ro.ro<UserCerts>(Tables::USER_CERTS)->get(retained_id) ==
      retained_identity.cert);
    REQUIRE(
      ro.ro<UserInfo>(Tables::USER_INFO)->get(retained_id)->user_data ==
      nlohmann::json{{"role", "retained"}});
  }
}

TEST_CASE("Rejected user data conflicts do not commit a certificate")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  const UserId user_id =
    ccf::crypto::Sha256Hash(ccf::crypto::cert_pem_to_der(identity.cert))
      .hex_str();
  const nlohmann::json data = {{"role", "original"}};
  {
    // set_user_data can create a data-only entry before a user is admitted.
    auto tx = store.create_tx();
    tx.rw<UserInfo>(Tables::USER_INFO)->put(user_id, {data});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const auto before = store.current_txid();
  {
    auto tx = store.create_tx();
    REQUIRE_THROWS_WITH_AS(
      InternalTablesAccess::add_user(
        tx, {identity.cert, {{"role", "replacement"}}}),
      fmt::format("User data already exists for user {}", user_id.value())
        .c_str(),
      std::logic_error);
  }
  REQUIRE(store.current_txid() == before);
  auto ro = store.create_read_only_tx();
  REQUIRE_FALSE(ro.ro<UserCerts>(Tables::USER_CERTS)->has(user_id));
  REQUIRE(ro.ro<UserInfo>(Tables::USER_INFO)->get(user_id)->user_data == data);
}

TEST_CASE("Service configuration is initialised once")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  {
    auto tx = store.create_read_only_tx();
    REQUIRE_THROWS_WITH_AS(
      InternalTablesAccess::get_recovery_threshold(tx),
      "Failed to get recovery threshold: No active configuration found",
      std::logic_error);
  }
  const ServiceConfiguration configuration{
    .recovery_threshold = 2,
    .maximum_node_certificate_validity_days = 10,
    .maximum_service_certificate_validity_days = 20};
  {
    auto tx = store.create_tx();
    InternalTablesAccess::init_configuration(tx, configuration);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const auto before = store.current_txid();
  {
    auto tx = store.create_tx();
    REQUIRE_THROWS_WITH_AS(
      InternalTablesAccess::init_configuration(tx, {3}),
      "Cannot initialise service configuration: configuration already exists",
      std::logic_error);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  REQUIRE(store.current_txid() == before);
  auto ro = store.create_read_only_tx();
  REQUIRE(InternalTablesAccess::get_recovery_threshold(ro) == 2);
  const auto stored = ro.ro<Configuration>(Tables::CONFIGURATION)->get();
  REQUIRE(stored.has_value());
  REQUIRE(nlohmann::json(stored.value()) == nlohmann::json(configuration));
}

TEST_CASE("Service queries distinguish missing, opening and recovering state")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  const TestIdentity other_identity;
  {
    auto ro = store.create_read_only_tx();
    REQUIRE_FALSE(InternalTablesAccess::get_service_status(ro).has_value());
    REQUIRE_FALSE(InternalTablesAccess::is_service_recovering(ro));
    REQUIRE_FALSE(InternalTablesAccess::is_service_created(ro, identity.cert));
  }
  const nlohmann::json data = {{"name", "service"}};
  const TxID create_txid{1, 1};
  {
    auto tx = store.create_tx();
    InternalTablesAccess::create_service(tx, identity.cert, create_txid, data);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  for (const auto status :
       {ServiceStatus::OPENING,
        ServiceStatus::OPEN,
        ServiceStatus::RECOVERING,
        ServiceStatus::WAITING_FOR_RECOVERY_SHARES})
  {
    CAPTURE(status);
    auto tx = store.create_tx();
    auto* service = tx.rw<Service>(Tables::SERVICE);
    auto info = service->get();
    REQUIRE(info.has_value());
    info->status = status;
    service->put(info.value());
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    auto ro = store.create_read_only_tx();
    REQUIRE(InternalTablesAccess::get_service_status(ro) == status);
    REQUIRE(
      InternalTablesAccess::is_service_recovering(ro) ==
      (status == ServiceStatus::RECOVERING ||
       status == ServiceStatus::WAITING_FOR_RECOVERY_SHARES));
    REQUIRE(InternalTablesAccess::is_service_created(ro, identity.cert));
    REQUIRE_FALSE(
      InternalTablesAccess::is_service_created(ro, other_identity.cert));
    const auto stored = ro.ro<Service>(Tables::SERVICE)->get();
    REQUIRE(stored->service_data == data);
    REQUIRE(stored->current_service_create_txid == create_txid);
    REQUIRE(stored->recovery_count == 0);
    REQUIRE_FALSE(stored->previous_service_identity_version.has_value());
  }
}

TEST_CASE("Opening counts active participants separately from owners")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity service_identity;
  const TestIdentity participant;
  const TestIdentity pending_participant;
  const TestIdentity owner;
  const auto encryption_key =
    ccf::crypto::make_rsa_key_pair()->public_key_pem();
  MemberId pending_id;
  {
    auto tx = store.create_tx();
    InternalTablesAccess::init_configuration(tx, {2});
    InternalTablesAccess::create_service(
      tx, service_identity.cert, {1, 1}, {{"name", "service"}});
    const auto participant_id = InternalTablesAccess::add_member(
      tx,
      {participant.cert,
       encryption_key,
       nullptr,
       MemberRecoveryRole::Participant});
    REQUIRE(InternalTablesAccess::activate_member(tx, participant_id));
    pending_id = InternalTablesAccess::add_member(
      tx, {pending_participant.cert, encryption_key});
    const auto owner_id = InternalTablesAccess::add_member(
      tx, {owner.cert, encryption_key, nullptr, MemberRecoveryRole::Owner});
    REQUIRE(InternalTablesAccess::activate_member(tx, owner_id));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const auto before = store.current_txid();
  {
    auto tx = store.create_tx();
    REQUIRE_FALSE(InternalTablesAccess::open_service(tx));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  REQUIRE(store.current_txid() == before);
  {
    auto ro = store.create_read_only_tx();
    REQUIRE(
      InternalTablesAccess::get_service_status(ro) == ServiceStatus::OPENING);
    REQUIRE(
      InternalTablesAccess::get_active_recovery_participants(ro).size() == 1);
    REQUIRE(InternalTablesAccess::get_active_recovery_owners(ro).size() == 1);
  }
  {
    auto tx = store.create_tx();
    REQUIRE(InternalTablesAccess::activate_member(tx, pending_id));
    REQUIRE(InternalTablesAccess::open_service(tx));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const auto after_opening = store.current_txid();
  {
    auto tx = store.create_tx();
    REQUIRE(InternalTablesAccess::open_service(tx));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  REQUIRE(store.current_txid() == after_opening);
  auto ro = store.create_read_only_tx();
  const auto service = ro.ro<Service>(Tables::SERVICE)->get();
  REQUIRE(service->status == ServiceStatus::OPEN);
  REQUIRE(service->cert == service_identity.cert);
  REQUIRE(service->service_data == nlohmann::json{{"name", "service"}});
  REQUIRE(
    InternalTablesAccess::get_active_recovery_participants(ro).size() == 2);
  REQUIRE(InternalTablesAccess::get_active_recovery_owners(ro).size() == 1);
}

TEST_CASE("An owner-only service can open once an owner is active")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity service_identity;
  const TestIdentity owner;
  MemberId owner_id;
  {
    auto tx = store.create_tx();
    InternalTablesAccess::init_configuration(tx, {1});
    InternalTablesAccess::create_service(tx, service_identity.cert, {1, 1});
    owner_id = InternalTablesAccess::add_member(
      tx,
      {owner.cert,
       ccf::crypto::make_rsa_key_pair()->public_key_pem(),
       nullptr,
       MemberRecoveryRole::Owner});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const auto before = store.current_txid();
  {
    auto tx = store.create_tx();
    REQUIRE_FALSE(InternalTablesAccess::open_service(tx));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  REQUIRE(store.current_txid() == before);
  {
    auto tx = store.create_tx();
    REQUIRE(InternalTablesAccess::activate_member(tx, owner_id));
    REQUIRE(InternalTablesAccess::get_active_recovery_participants(tx).empty());
    REQUIRE(InternalTablesAccess::get_active_recovery_owners(tx).size() == 1);
    REQUIRE(InternalTablesAccess::open_service(tx));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  auto ro = store.create_read_only_tx();
  REQUIRE(InternalTablesAccess::get_service_status(ro) == ServiceStatus::OPEN);
  REQUIRE(
    ro.ro<MemberInfo>(Tables::MEMBER_INFO)->get(owner_id)->status ==
    MemberStatus::ACTIVE);
}

TEST_CASE("Opening a missing service does not create it")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity participant;
  {
    auto tx = store.create_tx();
    InternalTablesAccess::init_configuration(tx, {1});
    const auto member_id = InternalTablesAccess::add_member(
      tx,
      {participant.cert, ccf::crypto::make_rsa_key_pair()->public_key_pem()});
    REQUIRE(InternalTablesAccess::activate_member(tx, member_id));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const auto before = store.current_txid();
  auto tx = store.create_tx();
  REQUIRE_FALSE(InternalTablesAccess::open_service(tx));
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(store.current_txid() == before);
  auto ro = store.create_read_only_tx();
  REQUIRE_FALSE(ro.ro<Service>(Tables::SERVICE)->has());
}

TEST_CASE("Identity endorsements link consecutive service recoveries")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const std::vector<TxID> creations = {{1, 1}, {3, 10}, {5, 20}};
  ccf::MerkleTreeHistory tree;
  std::optional<ccf::kv::Version> previous_endorsement_version;
  std::vector<uint8_t> previous_key;
  ccf::crypto::Pem previous_cert;

  for (size_t generation = 0; generation < creations.size(); ++generation)
  {
    CAPTURE(generation);
    const TestIdentity identity;
    {
      auto tx = store.create_tx();
      if (generation != 0)
      {
        tx.wo<ccf::SerialisedMerkleTree>(Tables::SERIALISED_MERKLE_TREE)
          ->put(tree.serialise());
      }
      InternalTablesAccess::create_service(
        tx,
        identity.cert,
        creations[generation],
        {{"generation", generation}},
        generation != 0);
      REQUIRE(
        InternalTablesAccess::endorse_previous_identity(tx, *identity.key));
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    auto ro = store.create_read_only_tx();
    auto* endorsements = ro.ro<ccf::PreviousServiceIdentityEndorsement>(
      Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT);
    const auto endorsement = endorsements->get(IdentityType::CLASSICAL);
    REQUIRE(endorsement.has_value());
    const auto expected_begin = creations[generation == 0 ? 0 : generation - 1];
    std::optional<TxID> expected_end;
    if (generation != 0)
    {
      expected_end =
        TxID{creations[generation - 1].view, creations[generation].seqno - 1};
    }
    REQUIRE(endorsement->endorsing_key == identity.key->public_key_der());
    REQUIRE(endorsement->endorsement_epoch_begin == expected_begin);
    REQUIRE(endorsement->endorsement_epoch_end == expected_end);
    REQUIRE(endorsement->previous_version == previous_endorsement_version);

    auto verifier =
      ccf::crypto::make_cose_verifier_from_key(identity.key->public_key_der());
    std::span<uint8_t> authenticated_key;
    REQUIRE(verifier->verify(endorsement->endorsement, authenticated_key));
    const auto& expected_key =
      generation == 0 ? endorsement->endorsing_key : previous_key;
    REQUIRE(std::ranges::equal(authenticated_key, expected_key));
    if (expected_end.has_value())
    {
      const auto validity = ccf::crypto::extract_cose_endorsement_validity(
        endorsement->endorsement);
      REQUIRE(validity.from_txid == expected_begin.to_str());
      REQUIRE(validity.to_txid == expected_end->to_str());
    }

    const auto service = ro.ro<Service>(Tables::SERVICE)->get();
    REQUIRE(service->cert == identity.cert);
    REQUIRE(service->current_service_create_txid == creations[generation]);
    REQUIRE(service->recovery_count == generation);
    REQUIRE(
      service->service_data == nlohmann::json{{"generation", generation}});
    if (generation != 0)
    {
      REQUIRE(service->status == ServiceStatus::RECOVERING);
      REQUIRE(
        service->previous_service_identity_version ==
        creations[generation - 1].seqno);
      REQUIRE(
        ro.ro<ccf::PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
          ->get() == previous_cert);
      REQUIRE(
        ro.ro<ccf::PreviousServiceLastSignedRoot>(
            Tables::PREVIOUS_SERVICE_LAST_SIGNED_ROOT)
          ->get() == tree.get_root());
    }

    previous_endorsement_version =
      endorsements->get_version_of_previous_write(IdentityType::CLASSICAL);
    previous_key = endorsement->endorsing_key;
    previous_cert = identity.cert;
    tree.append(ccf::crypto::Sha256Hash(identity.cert.str()));
  }
}

TEST_CASE("Failed recovery creation preserves the previous service")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity previous_identity;
  const TestIdentity next_identity;
  {
    auto tx = store.create_tx();
    InternalTablesAccess::create_service(
      tx, previous_identity.cert, {1, 1}, {{"name", "previous"}});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const char* expected_error =
    "Previous service doesn't have a serialised merkle tree";
  SUBCASE("Missing serialised Merkle tree") {}
  SUBCASE("Missing creation transaction")
  {
    auto tx = store.create_tx();
    auto* service = tx.rw<Service>(Tables::SERVICE);
    auto info = service->get().value();
    info.current_service_create_txid.reset();
    service->put(info);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    expected_error =
      "Starting TX for the previous service doesn't have "
      "current_service_create_txid recorded";
  }

  nlohmann::json previous_service;
  {
    auto ro = store.create_read_only_tx();
    previous_service = ro.ro<Service>(Tables::SERVICE)->get().value();
  }
  const auto before = store.current_txid();
  {
    auto tx = store.create_tx();
    REQUIRE_THROWS_WITH_AS(
      InternalTablesAccess::create_service(
        tx, next_identity.cert, {3, 10}, nullptr, true),
      expected_error,
      std::logic_error);
  }
  REQUIRE(store.current_txid() == before);
  auto ro = store.create_read_only_tx();
  REQUIRE(
    nlohmann::json(ro.ro<Service>(Tables::SERVICE)->get().value()) ==
    previous_service);
  const auto signing_identity =
    ro.ro<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES)
      ->get(IdentityType::CLASSICAL);
  REQUIRE(signing_identity.has_value());
  REQUIRE(
    signing_identity.value() ==
    Identity{
      IdentityKind::X509_SPKI_DER, previous_identity.key->public_key_der()});
  REQUIRE_FALSE(
    ro.ro<ccf::PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
      ->has());
  REQUIRE_FALSE(ro.ro<ccf::PreviousServiceLastSignedRoot>(
                    Tables::PREVIOUS_SERVICE_LAST_SIGNED_ROOT)
                  ->has());
}

TEST_CASE("Self-endorsement requires a service creation transaction")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  SUBCASE("No service") {}
  SUBCASE("No creation transaction")
  {
    auto tx = store.create_tx();
    tx.rw<Service>(Tables::SERVICE)->put(ServiceInfo{.cert = identity.cert});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const auto before = store.current_txid();
  auto tx = store.create_tx();
  REQUIRE_THROWS_WITH_AS(
    InternalTablesAccess::endorse_previous_identity(tx, *identity.key),
    "Active service or current_service_create_txid is not set",
    std::logic_error);
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(store.current_txid() == before);
  auto ro = store.create_read_only_tx();
  REQUIRE(
    ro.ro<ccf::PreviousServiceIdentityEndorsement>(
        Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
      ->size() == 0);
}

TEST_CASE("direct node deletion updates consensus configuration")
{
  const NodeId removed_id = std::string("removed");
  const NodeId other_removed_id = std::string("other_removed");
  const NodeId retained_id = std::string("retained");
  const NodeId unknown_id = std::string("unknown");
  TestConsensus consensus(
    {{removed_id, {"removed.example.com", "1234"}},
     {other_removed_id, {"other-removed.example.com", "2345"}},
     {retained_id, {"retained.example.com", "5678"}}});
  Nodes::Write node_writes = {
    {removed_id, std::nullopt},
    {other_removed_id, std::nullopt},
    {unknown_id, std::nullopt}};

  ConfigurationChangeHook(42, node_writes).call(&consensus);

  REQUIRE(consensus.configuration_version == 42);
  REQUIRE(consensus.configuration_changes == 1);
  REQUIRE_FALSE(consensus.configuration.contains(removed_id));
  REQUIRE_FALSE(consensus.configuration.contains(other_removed_id));
  REQUIRE(consensus.configuration.contains(retained_id));

  ConfigurationChangeHook(43, Nodes::Write{{unknown_id, std::nullopt}})
    .call(&consensus);

  REQUIRE(consensus.configuration_version == 42);
  REQUIRE(consensus.configuration_changes == 1);
}

TEST_CASE("trust_node_snp_tcb_version rejects an empty owner")
{
  ccf::kv::Store kv_store;
  auto tx = kv_store.create_tx();
  const pal::snp::AttestationReport report;
  CHECK_THROWS_WITH_AS(
    InternalTablesAccess::trust_node_snp_tcb_version(
      tx, report, false /* recovering */),
    "Cannot access an empty SNP attestation report",
    std::logic_error);
}

TEST_CASE("trust_node_snp_tcb_version - not recovering")
{
  ccf::kv::Store kv_store;
  kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

  const auto milan = pal::snp::ProductName::Milan;
  const auto cpuid = pal::snp::get_cpuid_of_snp_sev_product(milan);
  const auto reported = tcb_from_hex(milan, "db18000000000004");

  SUBCASE("Empty map") {}

  SUBCASE("Existing lower value")
  {
    set_min_tcb_version(
      kv_store, cpuid, tcb_from_hex(milan, "0000000000000000"));
  }

  trust_tcb_version(kv_store, cpuid, reported, false /* recovering */);

  REQUIRE(
    get_min_tcb_version(kv_store, cpuid).first == nlohmann::json(reported));
}

TEST_CASE("trust_node_snp_tcb_version - recovering")
{
  ccf::kv::Store kv_store;
  kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

  const auto milan = pal::snp::ProductName::Milan;
  const auto cpuid = pal::snp::get_cpuid_of_snp_sev_product(milan);
  // boot_loader 4, tee 0, snp 24, microcode 219
  const auto reported = tcb_from_hex(milan, "db18000000000004");

  // Entries for other CPUIDs are left untouched
  const auto genoa = pal::snp::ProductName::Genoa;
  const auto genoa_cpuid = pal::snp::get_cpuid_of_snp_sev_product(genoa);
  set_min_tcb_version(
    kv_store, genoa_cpuid, tcb_from_hex(genoa, "541700000000000a"));
  const auto genoa_entry = get_min_tcb_version(kv_store, genoa_cpuid);

  SUBCASE("No existing value for CPUID")
  {
    trust_tcb_version(kv_store, cpuid, reported, true /* recovering */);
    REQUIRE(
      get_min_tcb_version(kv_store, cpuid).first == nlohmann::json(reported));
  }

  SUBCASE("Existing value admits the reported TCB version")
  {
    pal::snp::TcbVersionPolicy existing;
    SUBCASE("Equal")
    {
      existing = reported;
    }
    SUBCASE("Lower")
    {
      // boot_loader 4, tee 0, snp 21, microcode 211
      existing = tcb_from_hex(milan, "d315000000000004");
    }
    SUBCASE("Lower, set without hexstring")
    {
      existing = {.microcode = 0, .snp = 0, .tee = 0, .boot_loader = 0};
    }
    set_min_tcb_version(kv_store, cpuid, existing);
    const auto existing_entry = get_min_tcb_version(kv_store, cpuid);

    trust_tcb_version(kv_store, cpuid, reported, true /* recovering */);

    // Neither modified nor re-written
    REQUIRE(get_min_tcb_version(kv_store, cpuid) == existing_entry);
  }

  SUBCASE("Existing value does not admit the reported TCB version")
  {
    pal::snp::TcbVersionPolicy existing;
    SUBCASE("Higher in every component")
    {
      // boot_loader 5, tee 1, snp 25, microcode 220
      existing = tcb_from_hex(milan, "dc19000000000105");
    }
    SUBCASE("Higher in some components and lower in others")
    {
      // boot_loader 5, tee 0, snp 28, microcode 211
      existing = tcb_from_hex(milan, "d31c000000000005");
    }
    SUBCASE("Has a component that Milan does not")
    {
      // As set_snp_minimum_tcb_version allows. Admits no Milan TCB version.
      existing = {
        .microcode = 0, .snp = 0, .tee = 0, .boot_loader = 0, .fmc = 0};
    }
    set_min_tcb_version(kv_store, cpuid, existing);

    trust_tcb_version(kv_store, cpuid, reported, true /* recovering */);

    // Replaced by the whole reported TCB version, including its hexstring,
    // rather than combined with the existing value component by component
    REQUIRE(
      get_min_tcb_version(kv_store, cpuid).first == nlohmann::json(reported));
  }

  REQUIRE(get_min_tcb_version(kv_store, genoa_cpuid) == genoa_entry);
}

TEST_CASE("trust_node_snp_tcb_version - recovering, Turin")
{
  ccf::kv::Store kv_store;
  kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

  const auto turin = pal::snp::ProductName::Turin;
  const auto cpuid = pal::snp::get_cpuid_of_snp_sev_product(turin);
  // fmc 85, boot_loader 68, tee 51, snp 34, microcode 17
  const auto reported = tcb_from_hex(turin, "1100000022334455");

  SUBCASE("Existing value admits the reported TCB version")
  {
    // fmc 80, boot_loader 68, tee 51, snp 34, microcode 17
    set_min_tcb_version(
      kv_store, cpuid, tcb_from_hex(turin, "1100000022334450"));
    const auto existing_entry = get_min_tcb_version(kv_store, cpuid);

    trust_tcb_version(kv_store, cpuid, reported, true /* recovering */);

    // Neither modified nor re-written
    REQUIRE(get_min_tcb_version(kv_store, cpuid) == existing_entry);
  }

  SUBCASE("Existing value does not admit the reported TCB version")
  {
    pal::snp::TcbVersionPolicy existing;
    SUBCASE("Higher in some components and lower in others")
    {
      // fmc 80, boot_loader 64, tee 64, snp 16, microcode 32
      existing = tcb_from_hex(turin, "2000000010404050");
    }
    SUBCASE("Has no fmc")
    {
      // As set_snp_minimum_tcb_version allows. Admits no Turin TCB version.
      existing = {.microcode = 0, .snp = 0, .tee = 0, .boot_loader = 0};
    }
    set_min_tcb_version(kv_store, cpuid, existing);

    trust_tcb_version(kv_store, cpuid, reported, true /* recovering */);

    REQUIRE(
      get_min_tcb_version(kv_store, cpuid).first == nlohmann::json(reported));
  }
}

TEST_CASE("trust_node_uvm_endorsements - not recovering, empty map")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  SNPUVMEndorsements table(Tables::NODE_SNP_UVM_ENDORSEMENTS);

  pal::UVMEndorsements endorsement{"did:x509:test", "test-feed", "42"};

  {
    auto tx = kv_store.create_tx();
    InternalTablesAccess::trust_node_uvm_endorsements(
      tx, endorsement, false /* recovering */);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_read_only_tx();
    auto handle = tx.ro(table);
    auto result = handle->get("did:x509:test");
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 1);
    auto it = result->find("test-feed");
    REQUIRE(it != result->end());
    REQUIRE(it->second.svn == "42");
  }
}

TEST_CASE("trust_node_uvm_endorsements - recovering, new DID not in map")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  SNPUVMEndorsements table(Tables::NODE_SNP_UVM_ENDORSEMENTS);

  // Pre-populate with an existing DID
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(table);
    FeedToEndorsementsDataMap existing;
    existing["existing-feed"] = {"100"};
    handle->put("did:x509:existing", existing);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Call with a different DID while recovering
  pal::UVMEndorsements endorsement{"did:x509:new", "new-feed", "50"};

  {
    auto tx = kv_store.create_tx();
    InternalTablesAccess::trust_node_uvm_endorsements(
      tx, endorsement, true /* recovering */);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Verify new DID was written
  {
    auto tx = kv_store.create_read_only_tx();
    auto handle = tx.ro(table);

    auto new_result = handle->get("did:x509:new");
    REQUIRE(new_result.has_value());
    REQUIRE(new_result->size() == 1);
    auto it = new_result->find("new-feed");
    REQUIRE(it != new_result->end());
    REQUIRE(it->second.svn == "50");

    // Prior contents unchanged
    auto existing_result = handle->get("did:x509:existing");
    REQUIRE(existing_result.has_value());
    REQUIRE(existing_result->size() == 1);
    auto eit = existing_result->find("existing-feed");
    REQUIRE(eit != existing_result->end());
    REQUIRE(eit->second.svn == "100");
  }
}

TEST_CASE("trust_node_uvm_endorsements - recovering, existing DID, new feed")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  SNPUVMEndorsements table(Tables::NODE_SNP_UVM_ENDORSEMENTS);

  // Pre-populate with an existing DID and feed
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(table);
    FeedToEndorsementsDataMap existing;
    existing["feed-A"] = {"100"};
    handle->put("did:x509:shared", existing);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Call with the same DID but a different feed while recovering
  pal::UVMEndorsements endorsement{"did:x509:shared", "feed-B", "75"};

  {
    auto tx = kv_store.create_tx();
    InternalTablesAccess::trust_node_uvm_endorsements(
      tx, endorsement, true /* recovering */);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Verify both feeds are present
  {
    auto tx = kv_store.create_read_only_tx();
    auto handle = tx.ro(table);

    auto result = handle->get("did:x509:shared");
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 2);

    auto it_a = result->find("feed-A");
    REQUIRE(it_a != result->end());
    REQUIRE(it_a->second.svn == "100");

    auto it_b = result->find("feed-B");
    REQUIRE(it_b != result->end());
    REQUIRE(it_b->second.svn == "75");
  }
}

TEST_CASE(
  "trust_node_uvm_endorsements - recovering, existing DID and feed, lower SVN")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  SNPUVMEndorsements table(Tables::NODE_SNP_UVM_ENDORSEMENTS);

  // Pre-populate with SVN 100, plus a separate unrelated DID
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(table);
    FeedToEndorsementsDataMap existing;
    existing["the-feed"] = {"100"};
    handle->put("did:x509:the-did", existing);

    FeedToEndorsementsDataMap other;
    other["other-feed"] = {"999"};
    handle->put("did:x509:other-did", other);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Call with strictly lower SVN while recovering
  pal::UVMEndorsements endorsement{"did:x509:the-did", "the-feed", "42"};

  {
    auto tx = kv_store.create_tx();
    InternalTablesAccess::trust_node_uvm_endorsements(
      tx, endorsement, true /* recovering */);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // SVN should be updated to the lower value
  {
    auto tx = kv_store.create_read_only_tx();
    auto handle = tx.ro(table);

    auto result = handle->get("did:x509:the-did");
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 1);
    auto it = result->find("the-feed");
    REQUIRE(it != result->end());
    REQUIRE(it->second.svn == "42");

    // Pre-existing unrelated DID is unchanged
    auto other_result = handle->get("did:x509:other-did");
    REQUIRE(other_result.has_value());
    REQUIRE(other_result->size() == 1);
    auto oit = other_result->find("other-feed");
    REQUIRE(oit != other_result->end());
    REQUIRE(oit->second.svn == "999");
  }
}

TEST_CASE(
  "trust_node_uvm_endorsements - recovering, existing DID and feed, higher "
  "SVN")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  SNPUVMEndorsements table(Tables::NODE_SNP_UVM_ENDORSEMENTS);

  // Pre-populate with SVN 42
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(table);
    FeedToEndorsementsDataMap existing;
    existing["the-feed"] = {"42"};
    handle->put("did:x509:the-did", existing);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Call with strictly higher SVN while recovering
  pal::UVMEndorsements endorsement{"did:x509:the-did", "the-feed", "100"};

  {
    auto tx = kv_store.create_tx();
    InternalTablesAccess::trust_node_uvm_endorsements(
      tx, endorsement, true /* recovering */);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Map should be unchanged - SVN stays at 42
  {
    auto tx = kv_store.create_read_only_tx();
    auto handle = tx.ro(table);

    auto result = handle->get("did:x509:the-did");
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 1);
    auto it = result->find("the-feed");
    REQUIRE(it != result->end());
    REQUIRE(it->second.svn == "42");
  }
}

TEST_CASE("remove_previous_service_nodes")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  Nodes nodes(Tables::NODES);
  NodeEndorsedCertificates node_endorsed_certificates(
    Tables::NODE_ENDORSED_CERTIFICATES);
  LocalSealingNodeIdMap local_sealing_node_ids(Tables::SEALING_RECOVERY_NAMES);
  SealedRecoveryKeys sealed_recovery_keys(Tables::SEALED_RECOVERY_KEYS);
  const NodeId trusted_id = std::string("trusted");
  const NodeId retired_id = std::string("retired");
  const NodeId retired_committed_id = std::string("retired_committed");
  const std::string trusted_sealing_name = "trusted";
  const std::string trusted_alternate_sealing_name = "trusted_alternate";
  const std::string retired_sealing_name = "retired";
  const std::string retired_committed_sealing_name = "retired_committed";

  {
    auto tx = kv_store.create_tx();
    auto nodes_handle = tx.rw(nodes);
    auto node_endorsed_certificates_handle = tx.rw(node_endorsed_certificates);
    auto local_sealing_node_ids_handle = tx.rw(local_sealing_node_ids);
    auto sealed_recovery_keys_handle = tx.rw(sealed_recovery_keys);
    const auto encryption_pub_key =
      ccf::crypto::make_ec_key_pair()->public_key_pem();

    NodeInfo trusted;
    trusted.encryption_pub_key = encryption_pub_key;
    trusted.status = NodeStatus::TRUSTED;
    nodes_handle->put(trusted_id, trusted);

    NodeInfo retired = trusted;
    retired.status = NodeStatus::RETIRED;
    nodes_handle->put(retired_id, retired);

    NodeInfo retired_committed = retired;
    retired_committed.retired_committed = true;
    nodes_handle->put(retired_committed_id, retired_committed);

    SealedRecoveryKey sealed_recovery_key;
    sealed_recovery_key.ciphertext = {0};
    sealed_recovery_key.pubkey = encryption_pub_key;
    for (const auto& node_id : {trusted_id, retired_id, retired_committed_id})
    {
      node_endorsed_certificates_handle->put(node_id, encryption_pub_key);
      sealed_recovery_keys_handle->put(node_id, sealed_recovery_key);
    }
    local_sealing_node_ids_handle->put(trusted_sealing_name, trusted_id);
    local_sealing_node_ids_handle->put(
      trusted_alternate_sealing_name, trusted_id);
    local_sealing_node_ids_handle->put(retired_sealing_name, retired_id);
    local_sealing_node_ids_handle->put(
      retired_committed_sealing_name, retired_committed_id);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_tx();
    InternalTablesAccess::remove_previous_service_nodes(tx);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_read_only_tx();
    auto nodes_handle = tx.ro(nodes);
    auto node_endorsed_certificates_handle = tx.ro(node_endorsed_certificates);
    auto local_sealing_node_ids_handle = tx.ro(local_sealing_node_ids);
    auto sealed_recovery_keys_handle = tx.ro(sealed_recovery_keys);
    for (const auto& node_id : {trusted_id, retired_id, retired_committed_id})
    {
      REQUIRE_FALSE(nodes_handle->get(node_id).has_value());
      REQUIRE_FALSE(
        node_endorsed_certificates_handle->get(node_id).has_value());
      REQUIRE_FALSE(sealed_recovery_keys_handle->get(node_id).has_value());
    }
    for (const auto& sealing_name :
         {trusted_sealing_name,
          trusted_alternate_sealing_name,
          retired_sealing_name,
          retired_committed_sealing_name})
    {
      REQUIRE_FALSE(
        local_sealing_node_ids_handle->get(sealing_name).has_value());
    }
  }
}

TEST_CASE("create_service publishes the classical signing identity")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  auto service_key = ccf::crypto::make_ec_key_pair();
  const auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now());
  const auto valid_to =
    ccf::crypto::compute_cert_valid_to_string(valid_from, 1);
  const auto service_cert =
    service_key->self_sign("CN=Service", valid_from, valid_to);
  const ccf::Identity expected_identity{
    ccf::IdentityKind::X509_SPKI_DER, service_key->public_key_der()};

  INFO("Creation publishes the existing service key, without a PQ identity");
  {
    auto tx = kv_store.create_tx();
    InternalTablesAccess::create_service(tx, service_cert, {1, 1});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_read_only_tx();
    auto* handle = tx.ro<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);
    REQUIRE(handle->size() == 1);
    REQUIRE(handle->get(ccf::IdentityType::CLASSICAL) == expected_identity);
    REQUIRE_FALSE(handle->get(ccf::IdentityType::PQ).has_value());
    REQUIRE(tx.ro<ccf::Service>(Tables::SERVICE)->get()->cert == service_cert);
  }

  SUBCASE("Recovering a service with a published signing identity") {}

  SUBCASE("Recovering a legacy service without the signing identities table")
  {
    auto tx = kv_store.create_tx();
    tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES)
      ->remove(ccf::IdentityType::CLASSICAL);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto recovered_key = ccf::crypto::make_ec_key_pair();
  const auto recovered_cert =
    recovered_key->self_sign("CN=Service", valid_from, valid_to);
  const ccf::Identity recovered_identity{
    ccf::IdentityKind::X509_SPKI_DER, recovered_key->public_key_der()};
  ccf::MerkleTreeHistory tree;

  INFO("Recovery publishes the new key and preserves legacy recovery state");
  {
    auto tx = kv_store.create_tx();
    tx.wo<ccf::SerialisedMerkleTree>(Tables::SERIALISED_MERKLE_TREE)
      ->put(tree.serialise());
    InternalTablesAccess::create_service(
      tx, recovered_cert, {2, 10}, nullptr, true /* recovering */);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_read_only_tx();
    auto* handle = tx.ro<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);
    REQUIRE(handle->size() == 1);
    REQUIRE(handle->get(ccf::IdentityType::CLASSICAL) == recovered_identity);
    REQUIRE_FALSE(handle->get(ccf::IdentityType::PQ).has_value());
    REQUIRE(recovered_identity != expected_identity);
    const auto service = tx.ro<ccf::Service>(Tables::SERVICE)->get();
    REQUIRE(service.has_value());
    REQUIRE(service->cert == recovered_cert);
    REQUIRE(service->status == ccf::ServiceStatus::RECOVERING);
    REQUIRE(
      tx.ro<ccf::PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
        ->get() == service_cert);
    REQUIRE(
      tx.ro<ccf::PreviousServiceLastSignedRoot>(
          Tables::PREVIOUS_SERVICE_LAST_SIGNED_ROOT)
        ->get() == tree.get_root());
  }
}

TEST_CASE("Signing identity lookup only falls back for legacy CLASSICAL state")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const auto service_key = ccf::crypto::make_ec_key_pair();
  const auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now());
  const auto service_cert = service_key->self_sign(
    "CN=Service",
    valid_from,
    ccf::crypto::compute_cert_valid_to_string(valid_from, 1));
  const ccf::Identity identity{
    ccf::IdentityKind::X509_SPKI_DER, service_key->public_key_der()};
  auto tx = store.create_tx();
  auto* service = tx.rw<ccf::Service>(Tables::SERVICE);
  service->put(ccf::ServiceInfo{.cert = service_cert});
  auto* signing_identities =
    tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);

  SUBCASE("Legacy certificate supplies only CLASSICAL")
  {
    REQUIRE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL) ==
      identity);
    REQUIRE_FALSE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::PQ).has_value());
  }

  SUBCASE("No identity is available without either source")
  {
    service->clear();
    REQUIRE_FALSE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL)
        .has_value());
  }

  SUBCASE("Published keys do not require a legacy certificate")
  {
    signing_identities->put(ccf::IdentityType::CLASSICAL, identity);
    service->put(ccf::ServiceInfo{.cert = service_key->public_key_pem()});
    REQUIRE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL) ==
      identity);
    REQUIRE_FALSE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::PQ).has_value());
  }

  SUBCASE("A populated table must contain CLASSICAL")
  {
    signing_identities->put(ccf::IdentityType::PQ, identity);
    REQUIRE_THROWS_WITH(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL),
      "Non-empty signing identities table has no CLASSICAL identity");
  }

  SUBCASE("A certificate entry must not be interpreted as a public key")
  {
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      {ccf::IdentityKind::X509_CERT_DER,
       ccf::crypto::cert_pem_to_der(service_cert)});
    REQUIRE_THROWS_WITH(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL),
      "Service signing identity must be a DER SubjectPublicKeyInfo");
  }
}
