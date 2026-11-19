// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/crypto/cose_key.h"
#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/eddsa_key_pair.h"
#include "ccf/crypto/mldsa_key_pair.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/service.h"
#include "crypto/cbor_helpers.h"
#include "crypto/cbor_tags.h"
#include "crypto/certs.h"
#include "crypto/cose.h"
#include "crypto/openssl/mldsa_support.h"
#include "service/tables/config.h"
#include "service/tables/signatures.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "kv/null_encryptor.h"
#include "kv/store.h"
#include "node/hooks.h"
#include "node/internal_tables_access.h"

#include <algorithm>
#include <doctest/doctest.h>
#include <tav/cbor.hpp>
#include <utility>

using namespace ccf;

namespace
{
  // ML-DSA parameter set of the test PQ certificates
  constexpr auto PQ_PARAMETER_SET = ccf::crypto::MLDSAParameterSet::ML_DSA_65;

  // ML-DSA service key, or nullptr as held by a node whose build has no ML-DSA
  ccf::crypto::MLDSAKeyPairPtr make_pq_key()
  {
    if (!ccf::crypto::mldsa_supported())
    {
      return nullptr;
    }
    return ccf::crypto::make_mldsa_key_pair(PQ_PARAMETER_SET);
  }

  // ML-DSA service certificate, or nullopt as sent by a node whose build has
  // no ML-DSA
  std::optional<ccf::crypto::Pem> make_pq_cert(
    const std::string& subject_name,
    const std::string& valid_from,
    const std::string& valid_to)
  {
    const auto pq_key = make_pq_key();
    if (pq_key == nullptr)
    {
      return std::nullopt;
    }
    return pq_key->self_sign(subject_name, valid_from, valid_to);
  }

  struct TestIdentity
  {
    std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> key =
      std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
        ccf::crypto::make_ec_key_pair());
    ccf::crypto::MLDSAKeyPairPtr pq_key = make_pq_key();
    ccf::crypto::Pem cert;
    std::optional<ccf::crypto::Pem> pq_cert;

    TestIdentity()
    {
      REQUIRE(key != nullptr);
      // These tests parse certificates and extract keys, not check validity.
      // Deliberately expired dates avoid a future expiry deadline.
      cert = key->self_sign("CN=test", "20200101000000Z", "20201231235959Z");
      if (pq_key != nullptr)
      {
        pq_cert =
          pq_key->self_sign("CN=test", "20200101000000Z", "20201231235959Z");
      }
    }
  };

  // Signing identity of a default service key, which is on P-384
  ccf::Identity expected_signing_identity(
    const std::vector<uint8_t>& public_key_der)
  {
    const auto public_key = ccf::crypto::make_ec_public_key(public_key_der);
    const ccf::crypto::COSEKey key(public_key);
    return {ccf::IdentityKind::COSE_KEY, key.to_cbor(ccf::cose::alg::ES384)};
  }

  std::optional<ccf::Identity> expected_pq_signing_identity(
    const std::optional<ccf::crypto::Pem>& cert)
  {
    if (!cert.has_value())
    {
      return std::nullopt;
    }
    const auto public_key_der =
      ccf::crypto::make_verifier(cert.value())->public_key_der();
    const auto key = ccf::crypto::COSEKey::from_der_public_key(public_key_der);
    const auto alg = ccf::cose::algorithm_for_parameter_set(PQ_PARAMETER_SET);
    return ccf::Identity{ccf::IdentityKind::COSE_KEY, key.to_cbor(alg)};
  }

  // The key endorsed by an endorsement, verified with its endorsing key
  std::vector<uint8_t> verified_endorsed_key(
    const ccf::CoseEndorsement& endorsement)
  {
    std::span<uint8_t> endorsed_key;
    REQUIRE(ccf::crypto::make_cose_verifier_from_key(endorsement.endorsing_key)
              ->verify(endorsement.endorsement, endorsed_key));
    return {endorsed_key.begin(), endorsed_key.end()};
  }

  std::vector<uint8_t> protected_header(const ccf::CoseEndorsement& endorsement)
  {
    const auto phdr = tav::cbor::nondet_parse(endorsement.endorsement)
                        .tag_at(ccf::cbor::tag::COSE_SIGN_1)
                        .array_at(0)
                        .as_bytes();
    return {phdr.begin(), phdr.end()};
  }

  // A PQ endorsement has the epochs, previous version and protected header,
  // except alg, of the CLASSICAL endorsement written with it
  void require_pq_matches_classical(
    const ccf::CoseEndorsement& pq, const ccf::CoseEndorsement& classical)
  {
    REQUIRE(pq.endorsement_epoch_begin == classical.endorsement_epoch_begin);
    REQUIRE(pq.endorsement_epoch_end == classical.endorsement_epoch_end);
    REQUIRE(pq.previous_version == classical.previous_version);
    const auto classical_header = protected_header(classical);
    REQUIRE(std::ranges::equal(
      ccf::cbor::with_entry(
        tav::cbor::nondet_parse(classical_header),
        ccf::cose::header::iana::ALG,
        tav::cbor::make_signed(
          ccf::cose::algorithm_for_parameter_set(PQ_PARAMETER_SET)))
        .det_serialize(),
      protected_header(pq)));
  }

  // Every encoding of the key decodes to its published identity, and a
  // trailing byte is rejected rather than ignored
  void require_encodings_round_trip(
    const ccf::Identity& identity,
    const std::vector<uint8_t>& spki,
    const ccf::crypto::Pem& cert)
  {
    const ccf::Identity spki_identity{IdentityKind::X509_SPKI_DER, spki};
    const ccf::Identity cert_identity{
      IdentityKind::X509_CERT_DER, ccf::crypto::cert_pem_to_der(cert)};
    for (const auto& encoded : {spki_identity, cert_identity, identity})
    {
      const auto key = ccf::cose_key_from_identity(encoded);
      REQUIRE(ccf::signing_identity_from_key(key) == identity);
    }

    auto trailing_spki = spki;
    trailing_spki.push_back(0);
    const ccf::Identity trailing_identity{
      IdentityKind::X509_SPKI_DER, trailing_spki};
    REQUIRE_THROWS_AS(
      ccf::cose_key_from_identity(trailing_identity), std::invalid_argument);
  }

  class TestConsensus : public ccf::kv::ConfigurableConsensus
  {
  public:
    ccf::kv::Configuration::Nodes configuration;
    ccf::SeqNo configuration_version = 0;
    size_t configuration_changes = 0;
    std::vector<std::pair<ccf::SeqNo, std::vector<NodeId>>>
      retired_committed_txs;
    std::vector<std::string> calls;

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
      calls.emplace_back("add_configuration");
    }

    void trace_retired_committed_tx(
      ccf::SeqNo seqno, const std::vector<NodeId>& node_ids) override
    {
      retired_committed_txs.emplace_back(seqno, node_ids);
      calls.emplace_back("trace_retired_committed_tx");
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
    InternalTablesAccess::create_service(
      tx, identity.cert, identity.pq_cert, create_txid, data);
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

TEST_CASE("Recovering a service with an ML-DSA identity needs ML-DSA support")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  // Only the presence of the certificate matters, so a classical certificate
  // stands in for the ML-DSA one on builds that cannot produce it
  const auto pq_cert = identity.pq_cert.value_or(identity.cert);

  {
    auto ro = store.create_read_only_tx();
    CHECK_NOTHROW(InternalTablesAccess::check_service_identity_supported(ro));
  }

  const auto store_service = [&](const std::optional<ccf::crypto::Pem>& pq) {
    auto tx = store.create_tx();
    tx.rw<Service>(Tables::SERVICE)
      ->put(
        {.cert = identity.cert, .pq_cert = pq, .status = ServiceStatus::OPEN});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  };

  store_service(std::nullopt);
  {
    auto ro = store.create_read_only_tx();
    CHECK_NOTHROW(InternalTablesAccess::check_service_identity_supported(ro));
  }

  store_service(pq_cert);
  {
    auto ro = store.create_read_only_tx();
    if (ccf::crypto::mldsa_supported())
    {
      CHECK_NOTHROW(InternalTablesAccess::check_service_identity_supported(ro));
    }
    else
    {
      CHECK_THROWS_WITH_AS(
        InternalTablesAccess::check_service_identity_supported(ro),
        "Cannot recover a ledger whose service has an ML-DSA identity with a "
        "build without ML-DSA support. Use a build with OpenSSL 3.5 or newer "
        "to recover this ledger.",
        std::logic_error);
    }
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
      tx,
      service_identity.cert,
      service_identity.pq_cert,
      {1, 1},
      {{"name", "service"}});
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
    InternalTablesAccess::create_service(
      tx, service_identity.cert, service_identity.pq_cert, {1, 1});
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
  std::vector<uint8_t> previous_pq_key;
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
        identity.pq_cert,
        creations[generation],
        {{"generation", generation}},
        generation != 0);
      REQUIRE(InternalTablesAccess::endorse_previous_identity(
        tx, *identity.key, identity.pq_key));
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

    INFO("The PQ chain links the same services, with the PQ keys");
    const auto pq_endorsement = endorsements->get(IdentityType::PQ);
    REQUIRE(pq_endorsement.has_value() == (identity.pq_key != nullptr));
    if (pq_endorsement.has_value())
    {
      REQUIRE(
        pq_endorsement->endorsing_key == identity.pq_key->public_key_der());
      require_pq_matches_classical(pq_endorsement.value(), endorsement.value());
      REQUIRE(
        verified_endorsed_key(pq_endorsement.value()) ==
        (generation == 0 ? pq_endorsement->endorsing_key : previous_pq_key));
      REQUIRE(
        endorsements->get_version_of_previous_write(IdentityType::PQ) ==
        endorsements->get_version_of_previous_write(IdentityType::CLASSICAL));
      previous_pq_key = pq_endorsement->endorsing_key;
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

namespace
{
  // Consecutive services, each a recovery of the previous one
  struct ServiceGenerations
  {
    ccf::kv::Store store;
    ccf::MerkleTreeHistory tree;
    size_t count = 0;

    ServiceGenerations()
    {
      store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
    }

    // Creates and opens the next service. A classical-only service has no PQ
    // identity, as one opened by a node whose build has no ML-DSA.
    void open(
      const TestIdentity& identity,
      const TxID& create_txid,
      bool classical_only = false)
    {
      auto tx = store.create_tx();
      if (count != 0)
      {
        tx.wo<ccf::SerialisedMerkleTree>(Tables::SERIALISED_MERKLE_TREE)
          ->put(tree.serialise());
      }
      InternalTablesAccess::create_service(
        tx, identity.cert, identity.pq_cert, create_txid, nullptr, count != 0);
      if (classical_only)
      {
        auto* service = tx.rw<Service>(Tables::SERVICE);
        auto info = service->get().value();
        info.pq_cert.reset();
        service->put(info);
        tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES)
          ->remove(IdentityType::PQ);
      }
      REQUIRE(InternalTablesAccess::endorse_previous_identity(
        tx, *identity.key, classical_only ? nullptr : identity.pq_key));
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      tree.append(ccf::crypto::Sha256Hash(identity.cert.str()));
      ++count;
    }

    std::optional<ccf::CoseEndorsement> endorsement(IdentityType identity_type)
    {
      auto ro = store.create_read_only_tx();
      return ro
        .ro<ccf::PreviousServiceIdentityEndorsement>(
          Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
        ->get(identity_type);
    }

    std::optional<ccf::kv::Version> write_version(IdentityType identity_type)
    {
      auto ro = store.create_read_only_tx();
      return ro
        .ro<ccf::PreviousServiceIdentityEndorsement>(
          Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
        ->get_version_of_previous_write(identity_type);
    }
  };

  void require_self_endorsement(
    const ccf::CoseEndorsement& endorsement,
    const ccf::crypto::MLDSAKeyPairPtr& key,
    const TxID& create_txid)
  {
    REQUIRE(endorsement.endorsing_key == key->public_key_der());
    REQUIRE(endorsement.endorsement_epoch_begin == create_txid);
    REQUIRE_FALSE(endorsement.endorsement_epoch_end.has_value());
    REQUIRE_FALSE(endorsement.previous_version.has_value());
    REQUIRE(verified_endorsed_key(endorsement) == endorsement.endorsing_key);
  }
}

TEST_CASE("A classical-only service is followed by a PQ self-endorsement")
{
  if (!ccf::crypto::mldsa_supported())
  {
    return;
  }

  ServiceGenerations services;
  const TestIdentity classical_only;
  services.open(classical_only, {2, 1}, true);
  REQUIRE(services.endorsement(IdentityType::CLASSICAL).has_value());
  REQUIRE_FALSE(services.endorsement(IdentityType::PQ).has_value());

  INFO("The first service with a PQ identity starts the PQ chain");
  const TestIdentity first_pq;
  services.open(first_pq, {4, 10});
  const auto classical = services.endorsement(IdentityType::CLASSICAL).value();
  REQUIRE(classical.endorsement_epoch_begin == TxID{2, 1});
  REQUIRE(classical.endorsement_epoch_end == TxID{2, 9});
  require_self_endorsement(
    services.endorsement(IdentityType::PQ).value(), first_pq.pq_key, {4, 10});
  const auto first_pq_version = services.write_version(IdentityType::PQ);
  REQUIRE(first_pq_version == services.write_version(IdentityType::CLASSICAL));

  INFO("The next service back-endorses it over the CLASSICAL epochs");
  const TestIdentity second_pq;
  services.open(second_pq, {6, 20});
  const auto next_classical =
    services.endorsement(IdentityType::CLASSICAL).value();
  const auto next_pq = services.endorsement(IdentityType::PQ).value();
  REQUIRE(next_pq.endorsing_key == second_pq.pq_key->public_key_der());
  REQUIRE(next_pq.endorsement_epoch_begin == TxID{4, 10});
  REQUIRE(next_pq.endorsement_epoch_end == TxID{4, 19});
  REQUIRE(next_pq.previous_version == first_pq_version);
  require_pq_matches_classical(next_pq, next_classical);
  REQUIRE(verified_endorsed_key(next_pq) == first_pq.pq_key->public_key_der());
}

TEST_CASE("The PQ chain restarts after a service without a PQ identity")
{
  if (!ccf::crypto::mldsa_supported())
  {
    return;
  }

  ServiceGenerations services;
  const TestIdentity first;
  services.open(first, {2, 1});
  const auto stale_pq_version = services.write_version(IdentityType::PQ);
  REQUIRE(stale_pq_version.has_value());

  INFO("A classical-only service leaves the PQ endorsement unchanged");
  const TestIdentity classical_only;
  services.open(classical_only, {4, 10}, true);
  REQUIRE(services.write_version(IdentityType::PQ) == stale_pq_version);
  REQUIRE(services.write_version(IdentityType::CLASSICAL) != stale_pq_version);

  INFO("The next service starts a new PQ chain with a self-endorsement");
  const TestIdentity next;
  services.open(next, {6, 20});
  require_self_endorsement(
    services.endorsement(IdentityType::PQ).value(), next.pq_key, {6, 20});
  const auto classical = services.endorsement(IdentityType::CLASSICAL).value();
  REQUIRE(classical.endorsement_epoch_begin == TxID{4, 10});
  REQUIRE(
    verified_endorsed_key(classical) == classical_only.key->public_key_der());
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
      tx,
      previous_identity.cert,
      previous_identity.pq_cert,
      {1, 1},
      {{"name", "previous"}});
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
        tx, next_identity.cert, next_identity.pq_cert, {3, 10}, nullptr, true),
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
    expected_signing_identity(previous_identity.key->public_key_der()));
  REQUIRE(
    ro.ro<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES)
      ->get(IdentityType::PQ) ==
    expected_pq_signing_identity(previous_identity.pq_cert));
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
    InternalTablesAccess::endorse_previous_identity(
      tx, *identity.key, identity.pq_key),
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

TEST_CASE("Endorsements must be signed by the service signing identity")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  const TestIdentity other_identity;
  {
    auto tx = store.create_tx();
    InternalTablesAccess::create_service(
      tx, identity.cert, identity.pq_cert, {1, 1});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const auto before = store.current_txid();
  {
    auto tx = store.create_tx();
    SUBCASE("Another CLASSICAL key")
    {
      REQUIRE_THROWS_WITH_AS(
        InternalTablesAccess::endorse_previous_identity(
          tx, *other_identity.key, identity.pq_key),
        "Endorsing key is not the CLASSICAL service signing identity",
        std::logic_error);
    }
    if (ccf::crypto::mldsa_supported())
    {
      SUBCASE("Another PQ key")
      {
        REQUIRE_THROWS_WITH_AS(
          InternalTablesAccess::endorse_previous_identity(
            tx, *identity.key, other_identity.pq_key),
          "Endorsing key is not the PQ service signing identity",
          std::logic_error);
      }
      SUBCASE("No PQ key for the PQ signing identity")
      {
        REQUIRE_THROWS_WITH_AS(
          InternalTablesAccess::endorse_previous_identity(
            tx, *identity.key, nullptr),
          "No ML-DSA service key for the published PQ service signing "
          "identity",
          std::logic_error);
      }
    }
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  REQUIRE(store.current_txid() == before);
  auto ro = store.create_read_only_tx();
  REQUIRE(
    ro.ro<ccf::PreviousServiceIdentityEndorsement>(
        Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
      ->size() == 0);
}

TEST_CASE("Endorsements require each published identity to match its cert")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  const TestIdentity other_identity;
  {
    auto tx = store.create_tx();
    InternalTablesAccess::create_service(
      tx, identity.cert, identity.pq_cert, {1, 1});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  {
    auto tx = store.create_tx();
    auto* signing_identities =
      tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);
    auto pq_key = identity.pq_key;
    SUBCASE("CLASSICAL")
    {
      signing_identities->put(
        IdentityType::CLASSICAL,
        expected_signing_identity(other_identity.key->public_key_der()));
    }
    if (ccf::crypto::mldsa_supported())
    {
      SUBCASE("PQ, with a PQ key")
      {
        signing_identities->put(
          IdentityType::PQ,
          expected_pq_signing_identity(other_identity.pq_cert).value());
      }
      SUBCASE("PQ, without a PQ key")
      {
        signing_identities->put(
          IdentityType::PQ,
          expected_pq_signing_identity(other_identity.pq_cert).value());
        pq_key = nullptr;
      }
    }
    REQUIRE_THROWS_WITH_AS(
      InternalTablesAccess::endorse_previous_identity(
        tx, *identity.key, pq_key),
      "Service signing identity does not match its service certificate",
      std::logic_error);
    // The transaction holds the mismatched identity, so it is checked for
    // endorsements written before the throw
    auto* endorsements = tx.ro<ccf::PreviousServiceIdentityEndorsement>(
      Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT);
    REQUIRE_FALSE(endorsements->has(IdentityType::CLASSICAL));
    REQUIRE_FALSE(endorsements->has(IdentityType::PQ));
  }
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

TEST_CASE("node write traces retired_committed before configuration change")
{
  const NodeId retired_committed_id = std::string("retired_committed");
  const NodeId retired_id = std::string("retired");
  const NodeId trusted_id = std::string("trusted");
  TestConsensus consensus({{retired_id, {"retired.example.com", "1234"}}});

  NodeInfo trusted;
  trusted.status = NodeStatus::TRUSTED;
  NodeInfo retired = trusted;
  retired.status = NodeStatus::RETIRED;
  NodeInfo retired_committed = retired;
  retired_committed.retired_committed = true;

  ConfigurationChangeHook(
    44,
    Nodes::Write{
      {retired_committed_id, retired_committed},
      {retired_id, retired},
      {trusted_id, trusted}})
    .call(&consensus);

  REQUIRE(
    consensus.calls ==
    std::vector<std::string>{
      "trace_retired_committed_tx", "add_configuration"});
  REQUIRE(consensus.retired_committed_txs.size() == 1);
  REQUIRE(consensus.retired_committed_txs[0].first == 44);
  REQUIRE(
    consensus.retired_committed_txs[0].second ==
    std::vector<NodeId>{retired_committed_id});
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

TEST_CASE("Service signing identities round-trip EC keys in every encoding")
{
  for (const auto curve :
       {ccf::crypto::CurveID::SECP256R1,
        ccf::crypto::CurveID::SECP384R1,
        ccf::crypto::CurveID::SECP521R1})
  {
    CAPTURE(curve);
    const auto key = ccf::crypto::make_ec_key_pair(curve);
    const auto cert =
      key->self_sign("CN=Service", "20200101000000Z", "20201231235959Z");
    const auto spki = key->public_key_der();
    const auto identity = ccf::signing_identity_from_cert(cert);
    REQUIRE(identity.kind == IdentityKind::COSE_KEY);
    const auto cose_key = ccf::cose_key_from_identity(identity);
    REQUIRE(cose_key.kty() == ccf::crypto::COSEKeyType::EC2);
    REQUIRE(cose_key.alg() == ccf::cose::algorithm_for_curve(curve).alg);
    REQUIRE(ccf::is_same_key(identity, spki));
    require_encodings_round_trip(identity, spki, cert);
  }
}

TEST_CASE("Service signing identities round-trip every ML-DSA parameter set")
{
  if (!ccf::crypto::mldsa_supported())
  {
    return;
  }

  using ccf::crypto::MLDSAParameterSet;
  const std::vector<std::pair<MLDSAParameterSet, int64_t>> parameter_sets{
    {MLDSAParameterSet::ML_DSA_44, ccf::cose::alg::ML_DSA_44},
    {MLDSAParameterSet::ML_DSA_65, ccf::cose::alg::ML_DSA_65},
    {MLDSAParameterSet::ML_DSA_87, ccf::cose::alg::ML_DSA_87}};
  for (const auto& [parameter_set, alg] : parameter_sets)
  {
    CAPTURE(parameter_set);
    const auto key = ccf::crypto::make_mldsa_key_pair(parameter_set);
    const auto cert =
      key->self_sign("CN=Service", "20200101000000Z", "20201231235959Z");
    const auto spki = key->public_key_der();
    const auto identity = ccf::signing_identity_from_cert(cert);
    REQUIRE(identity.kind == IdentityKind::COSE_KEY);
    const auto cose_key = ccf::cose_key_from_identity(identity);
    REQUIRE(cose_key.kty() == ccf::crypto::COSEKeyType::AKP);
    REQUIRE(cose_key.alg() == alg);
    REQUIRE(cose_key.akp_parameters()->pub == key->public_key_raw());
    REQUIRE(ccf::is_same_key(identity, spki));
    require_encodings_round_trip(identity, spki, cert);
  }
}

TEST_CASE("Service signing identities reject RSA and EdDSA keys")
{
  const ccf::crypto::COSEKey rsa_key(ccf::crypto::make_rsa_key_pair());
  const auto eddsa_public_key_pem =
    ccf::crypto::make_eddsa_key_pair()->public_key_pem();
  const ccf::crypto::COSEKey eddsa_key(
    ccf::crypto::make_eddsa_public_key(eddsa_public_key_pem));
  for (const auto& key : {rsa_key, eddsa_key})
  {
    REQUIRE_THROWS_WITH_AS(
      ccf::signing_identity_from_key(key),
      "Service signing key must be an EC or ML-DSA key",
      std::logic_error);
  }
}

TEST_CASE("create_service publishes the service signing identities")
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
  const auto expected_identity =
    expected_signing_identity(service_key->public_key_der());
  const auto pq_cert = make_pq_cert("CN=Service", valid_from, valid_to);
  const auto expected_pq_identity = expected_pq_signing_identity(pq_cert);

  INFO("Creation publishes both service keys when PQ is available");
  {
    auto tx = kv_store.create_tx();
    InternalTablesAccess::create_service(tx, service_cert, pq_cert, {1, 1});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_read_only_tx();
    auto* handle = tx.ro<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);
    const size_t expected_entries = pq_cert.has_value() ? 2 : 1;
    REQUIRE(handle->size() == expected_entries);
    REQUIRE(handle->get(ccf::IdentityType::CLASSICAL) == expected_identity);
    REQUIRE(handle->get(ccf::IdentityType::PQ) == expected_pq_identity);
    REQUIRE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL) ==
      expected_identity);
    REQUIRE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::PQ) ==
      expected_pq_identity);
    REQUIRE_NOTHROW(ccf::check_signing_identity_matches_service_cert(tx));
    const auto service = tx.ro<ccf::Service>(Tables::SERVICE)->get();
    REQUIRE(service->cert == service_cert);
    REQUIRE(service->pq_cert == pq_cert);
  }

  SUBCASE("Recovering a service with a published signing identity") {}

  SUBCASE("Recovering a legacy service without the signing identities table")
  {
    auto tx = kv_store.create_tx();
    tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES)->clear();
    auto* service = tx.rw<ccf::Service>(Tables::SERVICE);
    auto info = service->get().value();
    info.pq_cert.reset();
    service->put(info);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto recovered_key = ccf::crypto::make_ec_key_pair();
  const auto recovered_cert =
    recovered_key->self_sign("CN=Service", valid_from, valid_to);
  const auto recovered_identity =
    expected_signing_identity(recovered_key->public_key_der());
  const auto recovered_pq_cert =
    make_pq_cert("CN=Service", valid_from, valid_to);
  const auto recovered_pq_identity =
    expected_pq_signing_identity(recovered_pq_cert);
  ccf::MerkleTreeHistory tree;

  INFO("Recovery publishes the new key and preserves legacy recovery state");
  {
    auto tx = kv_store.create_tx();
    tx.wo<ccf::SerialisedMerkleTree>(Tables::SERIALISED_MERKLE_TREE)
      ->put(tree.serialise());
    InternalTablesAccess::create_service(
      tx,
      recovered_cert,
      recovered_pq_cert,
      {2, 10},
      nullptr,
      true /* recovering */);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_read_only_tx();
    auto* handle = tx.ro<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);
    const size_t expected_entries = recovered_pq_cert.has_value() ? 2 : 1;
    REQUIRE(handle->size() == expected_entries);
    REQUIRE(handle->get(ccf::IdentityType::CLASSICAL) == recovered_identity);
    REQUIRE(handle->get(ccf::IdentityType::PQ) == recovered_pq_identity);
    REQUIRE(recovered_identity != expected_identity);
    if (recovered_pq_identity.has_value())
    {
      REQUIRE(recovered_pq_identity != expected_pq_identity);
    }
    REQUIRE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL) ==
      recovered_identity);
    REQUIRE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::PQ) ==
      recovered_pq_identity);
    REQUIRE_NOTHROW(ccf::check_signing_identity_matches_service_cert(tx));
    const auto service = tx.ro<ccf::Service>(Tables::SERVICE)->get();
    REQUIRE(service.has_value());
    REQUIRE(service->cert == recovered_cert);
    REQUIRE(service->pq_cert == recovered_pq_cert);
    REQUIRE(service->status == ccf::ServiceStatus::RECOVERING);
    auto* previous_identity =
      tx.ro<ccf::PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY);
    REQUIRE(previous_identity->get() == service_cert);
    auto* previous_root = tx.ro<ccf::PreviousServiceLastSignedRoot>(
      Tables::PREVIOUS_SERVICE_LAST_SIGNED_ROOT);
    REQUIRE(previous_root->get() == tree.get_root());
  }
}

TEST_CASE("create_service rejects invalid or missing PQ certificates")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  auto tx = store.create_tx();
  auto* service = tx.rw<ccf::Service>(Tables::SERVICE);
  auto* signing_identities =
    tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);

  SUBCASE("New services require PQ only on ML-DSA builds")
  {
    if (!ccf::crypto::mldsa_supported())
    {
      REQUIRE_NOTHROW(InternalTablesAccess::create_service(
        tx, identity.cert, std::nullopt, {1, 1}));
      REQUIRE_FALSE(service->get()->pq_cert.has_value());
      REQUIRE_FALSE(signing_identities->has(IdentityType::PQ));
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      return;
    }
    REQUIRE_THROWS_WITH_AS(
      InternalTablesAccess::create_service(
        tx, identity.cert, std::nullopt, {1, 1}),
      "An ML-DSA service certificate is required",
      std::logic_error);
  }

  SUBCASE("An existing PQ entry cannot be silently retained or discarded")
  {
    const auto previous =
      expected_signing_identity(identity.key->public_key_der());
    signing_identities->put(IdentityType::PQ, previous);
    REQUIRE_THROWS_WITH_AS(
      InternalTablesAccess::create_service(
        tx, identity.cert, std::nullopt, {1, 1}),
      "An ML-DSA service certificate is required",
      std::logic_error);
    REQUIRE(signing_identities->get(IdentityType::PQ) == previous);
    signing_identities->remove(IdentityType::PQ);
  }

  SUBCASE("An existing PQ certificate cannot be silently discarded")
  {
    const ServiceInfo previous{.cert = identity.cert, .pq_cert = identity.cert};
    service->put(previous);
    REQUIRE_THROWS_WITH_AS(
      InternalTablesAccess::create_service(
        tx, identity.cert, std::nullopt, {3, 10}, nullptr, true),
      "An ML-DSA service certificate is required",
      std::logic_error);
    const auto unchanged = service->get();
    REQUIRE(unchanged.has_value());
    REQUIRE(nlohmann::json(unchanged.value()) == nlohmann::json(previous));
    service->clear();
  }

  SUBCASE("An EC certificate is not a PQ identity")
  {
    REQUIRE_THROWS_WITH_AS(
      InternalTablesAccess::create_service(
        tx, identity.cert, identity.cert, {1, 1}),
      "PQ service signing key must be an ML-DSA key",
      std::logic_error);
  }

  SUBCASE("ML-DSA cannot replace the classical service certificate")
  {
    if (identity.pq_cert.has_value())
    {
      REQUIRE_THROWS_WITH_AS(
        InternalTablesAccess::create_service(
          tx, identity.pq_cert.value(), identity.pq_cert, {1, 1}),
        "Classical service signing key must be an EC key",
        std::logic_error);
    }
  }

  REQUIRE_FALSE(service->has());
  REQUIRE(signing_identities->size() == 0);
  auto* previous_identity =
    tx.ro<ccf::PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY);
  REQUIRE_FALSE(previous_identity->has());
  auto* previous_root = tx.ro<ccf::PreviousServiceLastSignedRoot>(
    Tables::PREVIOUS_SERVICE_LAST_SIGNED_ROOT);
  REQUIRE_FALSE(previous_root->has());
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
}

TEST_CASE("Signing identity lookup prefers the table over the certificate")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity service_identity;
  const TestIdentity other_identity;
  const auto service_key =
    expected_signing_identity(service_identity.key->public_key_der());
  const auto other_key =
    expected_signing_identity(other_identity.key->public_key_der());

  auto tx = store.create_tx();
  auto* service = tx.rw<ccf::Service>(Tables::SERVICE);
  service->put(ccf::ServiceInfo{.cert = service_identity.cert});
  auto* signing_identities =
    tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);

  SUBCASE("An empty table falls back to the certificate")
  {
    REQUIRE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL) ==
      service_key);
  }

  SUBCASE("A mismatched entry is rejected")
  {
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      {ccf::IdentityKind::X509_SPKI_DER, other_identity.key->public_key_der()});
    REQUIRE_THROWS_WITH_AS(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL),
      "Service signing identity does not match its service certificate",
      std::logic_error);
  }

  SUBCASE("Entries do not require service information")
  {
    signing_identities->put(ccf::IdentityType::CLASSICAL, service_key);
    service->clear();
    REQUIRE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL) ==
      service_key);
  }

  SUBCASE("No identity is available without either source")
  {
    service->clear();
    REQUIRE_FALSE(
      ccf::get_service_signing_identity(tx, ccf::IdentityType::CLASSICAL)
        .has_value());
  }
}

TEST_CASE("Signing identity check matches the table against the certificate")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity service_identity;
  const TestIdentity other_identity;

  auto tx = store.create_tx();
  auto* service = tx.rw<ccf::Service>(Tables::SERVICE);
  service->put(ccf::ServiceInfo{.cert = service_identity.cert});
  auto* signing_identities =
    tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);

  SUBCASE("Nothing to check without an entry or without service information")
  {
    REQUIRE_NOTHROW(ccf::check_signing_identity_matches_service_cert(tx));
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      expected_signing_identity(other_identity.key->public_key_der()));
    service->clear();
    REQUIRE_NOTHROW(ccf::check_signing_identity_matches_service_cert(tx));
  }

  SUBCASE("Matching entries pass in any encoding")
  {
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      expected_signing_identity(service_identity.key->public_key_der()));
    REQUIRE_NOTHROW(ccf::check_signing_identity_matches_service_cert(tx));
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      {ccf::IdentityKind::X509_SPKI_DER,
       service_identity.key->public_key_der()});
    REQUIRE_NOTHROW(ccf::check_signing_identity_matches_service_cert(tx));
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      {ccf::IdentityKind::X509_CERT_DER,
       ccf::crypto::cert_pem_to_der(service_identity.cert)});
    REQUIRE_NOTHROW(ccf::check_signing_identity_matches_service_cert(tx));
  }

  SUBCASE("An entry for another key is rejected")
  {
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      expected_signing_identity(other_identity.key->public_key_der()));
    REQUIRE_THROWS_WITH_AS(
      ccf::check_signing_identity_matches_service_cert(tx),
      "Service signing identity does not match its service certificate",
      std::logic_error);
  }
}

TEST_CASE("PQ signing identity reads never fall back to another source")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  auto tx = store.create_tx();
  auto* service = tx.rw<ccf::Service>(Tables::SERVICE);
  auto* signing_identities =
    tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);
  service->put(ServiceInfo{.cert = identity.cert});
  signing_identities->put(
    IdentityType::CLASSICAL,
    expected_signing_identity(identity.key->public_key_der()));

  SUBCASE("A classical-only service has no PQ signing identity")
  {
    REQUIRE_FALSE(
      ccf::get_service_signing_identity(tx, IdentityType::PQ).has_value());
    REQUIRE_NOTHROW(ccf::check_signing_identity_matches_service_cert(tx));
    service->clear();
    REQUIRE_FALSE(
      ccf::get_service_signing_identity(tx, IdentityType::PQ).has_value());
    return;
  }

  SUBCASE("A PQ certificate without a published key is rejected")
  {
    // Only the presence of the certificate matters here, so any certificate
    // serves on builds without ML-DSA
    const auto pq_cert = identity.pq_cert.value_or(identity.cert);
    service->put(ServiceInfo{.cert = identity.cert, .pq_cert = pq_cert});
  }

  SUBCASE("A PQ entry without a PQ certificate is rejected")
  {
    signing_identities->put(
      IdentityType::PQ,
      expected_signing_identity(identity.key->public_key_der()));
  }

  SUBCASE("A PQ entry without service information is rejected")
  {
    signing_identities->put(
      IdentityType::PQ,
      expected_signing_identity(identity.key->public_key_der()));
    service->clear();
  }

  REQUIRE_THROWS_WITH_AS(
    ccf::get_service_signing_identity(tx, IdentityType::PQ),
    "PQ signing identity and service certificate must both be present or "
    "absent",
    std::logic_error);
  REQUIRE_THROWS_WITH_AS(
    ccf::check_signing_identity_matches_service_cert(tx),
    "PQ signing identity and service certificate must both be present or "
    "absent",
    std::logic_error);
}

TEST_CASE("PQ signing identity reads require the matching ML-DSA COSE_Key")
{
  if (!ccf::crypto::mldsa_supported())
  {
    return;
  }

  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  const auto expected = expected_pq_signing_identity(identity.pq_cert);
  REQUIRE(expected.has_value());
  auto tx = store.create_tx();
  tx.rw<ccf::Service>(Tables::SERVICE)
    ->put(ServiceInfo{.cert = identity.cert, .pq_cert = identity.pq_cert});
  auto* signing_identities =
    tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);
  signing_identities->put(IdentityType::PQ, expected.value());

  SUBCASE("A matching entry is returned unchanged")
  {
    REQUIRE(
      ccf::get_service_signing_identity(tx, IdentityType::PQ) == expected);
    REQUIRE_NOTHROW(ccf::check_signing_identity_matches_service_cert(tx));
  }

  SUBCASE("A different ML-DSA public key is rejected")
  {
    const TestIdentity other;
    const auto other_pq_identity = expected_pq_signing_identity(other.pq_cert);
    REQUIRE(other_pq_identity.has_value());
    signing_identities->put(IdentityType::PQ, other_pq_identity.value());
    REQUIRE_THROWS_WITH_AS(
      ccf::get_service_signing_identity(tx, IdentityType::PQ),
      "Service signing identity does not match its service certificate",
      std::logic_error);
    REQUIRE_THROWS_AS(
      ccf::check_signing_identity_matches_service_cert(tx), std::logic_error);
  }

  SUBCASE("An EC COSE_Key cannot substitute for PQ")
  {
    signing_identities->put(
      IdentityType::PQ,
      expected_signing_identity(identity.key->public_key_der()));
    REQUIRE_THROWS_WITH_AS(
      ccf::get_service_signing_identity(tx, IdentityType::PQ),
      "PQ signing identity must be an ML-DSA COSE_Key",
      std::logic_error);
    REQUIRE_THROWS_AS(
      ccf::check_signing_identity_matches_service_cert(tx), std::logic_error);
  }

  SUBCASE("PQ entries require COSE_Key encoding even for the same key")
  {
    const auto& pq_cert = identity.pq_cert.value();
    const auto pq_public_key_der =
      ccf::crypto::make_verifier(pq_cert)->public_key_der();
    const Identity spki_entry{IdentityKind::X509_SPKI_DER, pq_public_key_der};
    const Identity cert_entry{
      IdentityKind::X509_CERT_DER, ccf::crypto::cert_pem_to_der(pq_cert)};
    for (const auto& entry : {spki_entry, cert_entry})
    {
      signing_identities->put(IdentityType::PQ, entry);
      REQUIRE_THROWS_WITH_AS(
        ccf::get_service_signing_identity(tx, IdentityType::PQ),
        "PQ signing identity must be an ML-DSA COSE_Key",
        std::logic_error);
      REQUIRE_THROWS_AS(
        ccf::check_signing_identity_matches_service_cert(tx), std::logic_error);
    }
  }

  SUBCASE("A malformed COSE_Key is rejected")
  {
    signing_identities->put(
      IdentityType::PQ, Identity{IdentityKind::COSE_KEY, {0xff}});
    REQUIRE_THROWS_AS(
      ccf::get_service_signing_identity(tx, IdentityType::PQ),
      std::invalid_argument);
    REQUIRE_THROWS_AS(
      ccf::check_signing_identity_matches_service_cert(tx),
      std::invalid_argument);
  }
}

TEST_CASE("PQ signing identity encoding is checked before parsing")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const TestIdentity identity;
  auto tx = store.create_tx();
  // The encoding check precedes any parsing, so the PQ certificate only needs
  // to be present and this test does not need ML-DSA support
  tx.rw<ccf::Service>(Tables::SERVICE)
    ->put(ServiceInfo{.cert = identity.cert, .pq_cert = identity.cert});
  auto* signing_identities =
    tx.rw<ccf::SigningIdentities>(Tables::SIGNING_IDENTITIES);

  // Unparseable on every build: a parser error would be std::invalid_argument
  for (const auto kind :
       {IdentityKind::X509_SPKI_DER, IdentityKind::X509_CERT_DER})
  {
    signing_identities->put(IdentityType::PQ, Identity{kind, {0xff}});
    REQUIRE_THROWS_WITH_AS(
      ccf::get_service_signing_identity(tx, IdentityType::PQ),
      "PQ signing identity must be an ML-DSA COSE_Key",
      std::logic_error);
    REQUIRE_THROWS_WITH_AS(
      ccf::check_signing_identity_matches_service_cert(tx),
      "PQ signing identity must be an ML-DSA COSE_Key",
      std::logic_error);
  }
}
