// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/kv/map.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "crypto/openssl/hash.h"
#include "ds/internal_logger.h"
#include "kv/test/null_encryptor.h"
#include "node/network_state.h"
#include "service/internal_tables_access.h"

#include <doctest/doctest.h>

using namespace ccf;

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

TEST_CASE(
  "trust_node_uvm_endorsements - recovering, existing DID, new feed")
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
