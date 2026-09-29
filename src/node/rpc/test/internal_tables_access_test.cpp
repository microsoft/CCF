// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
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

#include <doctest/doctest.h>

using namespace ccf;

namespace
{
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

  pal::snp::CPUID get_snp_cpuid(pal::snp::ProductName product)
  {
    return pal::snp::cpuid_from_hex(
      pal::snp::get_cpuid_of_snp_sev_product(product));
  }

  pal::snp::TcbVersionPolicy make_tcb_policy(
    pal::snp::ProductName product, const std::string& tcb_hex)
  {
    return pal::snp::TcbVersionRaw::from_hex(tcb_hex).to_policy(product);
  }

  void set_min_tcb_version(
    ccf::kv::Store& kv_store,
    pal::snp::ProductName product,
    const pal::snp::TcbVersionPolicy& policy)
  {
    auto tx = kv_store.create_tx();
    tx.wo<SnpTcbVersionMap>(Tables::SNP_TCB_VERSIONS)
      ->put(get_snp_cpuid(product).hex_str(), policy);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  void trust_reported_tcb_version(
    ccf::kv::Store& kv_store,
    pal::snp::ProductName product,
    const std::string& reported_tcb_hex,
    bool recovering)
  {
    auto tx = kv_store.create_tx();
    InternalTablesAccess::trust_node_snp_tcb_version(
      tx,
      get_snp_cpuid(product),
      pal::snp::TcbVersionRaw::from_hex(reported_tcb_hex),
      recovering);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Returns the stored minimum TCB version as JSON, to compare all its fields,
  // and the version at which it was last written
  std::pair<nlohmann::json, ccf::kv::Version> get_min_tcb_version(
    ccf::kv::Store& kv_store, pal::snp::ProductName product)
  {
    auto tx = kv_store.create_read_only_tx();
    auto* handle = tx.ro<SnpTcbVersionMap>(Tables::SNP_TCB_VERSIONS);
    const auto cpuid_hex = get_snp_cpuid(product).hex_str();
    const auto policy = handle->get(cpuid_hex);
    REQUIRE(policy.has_value());
    const auto version = handle->get_version_of_previous_write(cpuid_hex);
    REQUIRE(version.has_value());
    return {nlohmann::json(policy.value()), version.value()};
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
  const std::string reported_tcb = "db18000000000004";

  SUBCASE("Empty map") {}

  SUBCASE("Existing lower value")
  {
    set_min_tcb_version(
      kv_store, milan, make_tcb_policy(milan, "0000000000000000"));
  }

  trust_reported_tcb_version(
    kv_store, milan, reported_tcb, false /* recovering */);

  REQUIRE(
    get_min_tcb_version(kv_store, milan).first ==
    nlohmann::json(make_tcb_policy(milan, reported_tcb)));
}

TEST_CASE("trust_node_snp_tcb_version - recovering")
{
  ccf::kv::Store kv_store;
  kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

  const auto milan = pal::snp::ProductName::Milan;
  // boot_loader 4, tee 0, snp 24, microcode 219
  const std::string reported_tcb = "db18000000000004";

  // Entries for other CPUIDs are left untouched
  const auto genoa = pal::snp::ProductName::Genoa;
  set_min_tcb_version(
    kv_store, genoa, make_tcb_policy(genoa, "541700000000000a"));
  const auto genoa_entry = get_min_tcb_version(kv_store, genoa);

  SUBCASE("No existing value for CPUID")
  {
    trust_reported_tcb_version(
      kv_store, milan, reported_tcb, true /* recovering */);
    REQUIRE(
      get_min_tcb_version(kv_store, milan).first ==
      nlohmann::json(make_tcb_policy(milan, reported_tcb)));
  }

  SUBCASE("Existing value is not higher in any component")
  {
    pal::snp::TcbVersionPolicy existing;
    SUBCASE("Equal")
    {
      existing = make_tcb_policy(milan, reported_tcb);
    }
    SUBCASE("Lower")
    {
      // boot_loader 4, tee 0, snp 21, microcode 211
      existing = make_tcb_policy(milan, "d315000000000004");
    }
    SUBCASE("Lower, set without hexstring")
    {
      existing = pal::snp::TcbVersionPolicy{
        .microcode = 0, .snp = 0, .tee = 0, .boot_loader = 0};
    }
    set_min_tcb_version(kv_store, milan, existing);
    const auto existing_entry = get_min_tcb_version(kv_store, milan);
    REQUIRE(existing_entry.first == nlohmann::json(existing));

    trust_reported_tcb_version(
      kv_store, milan, reported_tcb, true /* recovering */);

    // Neither modified nor re-written
    REQUIRE(get_min_tcb_version(kv_store, milan) == existing_entry);
  }

  SUBCASE("Existing value is higher in every component")
  {
    // boot_loader 5, tee 1, snp 25, microcode 220
    set_min_tcb_version(
      kv_store, milan, make_tcb_policy(milan, "dc19000000000105"));
    trust_reported_tcb_version(
      kv_store, milan, reported_tcb, true /* recovering */);
    REQUIRE(
      get_min_tcb_version(kv_store, milan).first ==
      nlohmann::json(make_tcb_policy(milan, reported_tcb)));
  }

  SUBCASE("Existing value is higher in some components and lower in others")
  {
    // boot_loader 5, tee 0, snp 28, microcode 211
    set_min_tcb_version(
      kv_store, milan, make_tcb_policy(milan, "d31c000000000005"));
    trust_reported_tcb_version(
      kv_store, milan, reported_tcb, true /* recovering */);
    // boot_loader 4, tee 0, snp 24, microcode 211
    REQUIRE(
      get_min_tcb_version(kv_store, milan).first ==
      nlohmann::json(make_tcb_policy(milan, "d318000000000004")));
  }

  REQUIRE(get_min_tcb_version(kv_store, genoa) == genoa_entry);
}

TEST_CASE("trust_node_snp_tcb_version - recovering, Turin")
{
  ccf::kv::Store kv_store;
  kv_store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());

  const auto turin = pal::snp::ProductName::Turin;
  // fmc 85, boot_loader 68, tee 51, snp 34, microcode 17
  const std::string reported_tcb = "1100000022334455";

  SUBCASE("Existing value is higher in some components and lower in others")
  {
    // fmc 80, boot_loader 64, tee 64, snp 16, microcode 32
    set_min_tcb_version(
      kv_store, turin, make_tcb_policy(turin, "2000000010404050"));
    trust_reported_tcb_version(
      kv_store, turin, reported_tcb, true /* recovering */);
    // fmc 80, boot_loader 64, tee 51, snp 16, microcode 17
    REQUIRE(
      get_min_tcb_version(kv_store, turin).first ==
      nlohmann::json(make_tcb_policy(turin, "1100000010334050")));
  }

  SUBCASE("Existing value has no fmc")
  {
    // As set_snp_minimum_tcb_version allows. Such a minimum admits no Turin
    // TCB version, so the reported fmc is kept.
    set_min_tcb_version(
      kv_store,
      turin,
      pal::snp::TcbVersionPolicy{
        .microcode = 0, .snp = 0, .tee = 0, .boot_loader = 0});
    trust_reported_tcb_version(
      kv_store, turin, reported_tcb, true /* recovering */);
    // fmc 85, boot_loader 0, tee 0, snp 0, microcode 0
    REQUIRE(
      get_min_tcb_version(kv_store, turin).first ==
      nlohmann::json(make_tcb_policy(turin, "0000000000000055")));
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
