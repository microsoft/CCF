// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/service.h"
#include "service/tables/config.h"
#include "service/tables/signatures.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "node/hooks.h"
#include "service/internal_tables_access.h"

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
