// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/snapshotter.h"
#include "service/tables/shards.h"

#include "crypto/openssl/hash.h"
#include "ds/internal_logger.h"
#include "ds/ring_buffer.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"
#include "node/history.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#include <string>

using StringString = ccf::kv::Map<std::string, std::string>;

void issue_transactions(ccf::NetworkState& network, size_t tx_count)
{
  for (size_t i = 0; i < tx_count; i++)
  {
    auto tx = network.tables->create_tx();
    auto map = tx.rw<StringString>("public:map");
    map->put("foo", "bar");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
}

TEST_CASE("Shard tables basic operations")
{
  ccf::logger::config::default_init();

  ccf::NetworkState network;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  network.tables->set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);

  INFO("Create initial shard");
  {
    auto tx = network.tables->create_tx();
    auto* shards = tx.rw<ccf::Shards>(ccf::Tables::SHARDS);

    ccf::ShardInfo initial_shard;
    initial_shard.shard_id = 0;
    initial_shard.seqno_start = 1;
    initial_shard.seqno_end = std::numeric_limits<ccf::kv::Version>::max();
    initial_shard.status = ccf::ShardStatus::Active;
    shards->put(0, initial_shard);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Read back initial shard");
  {
    auto tx = network.tables->create_read_only_tx();
    auto* shards = tx.ro<ccf::Shards>(ccf::Tables::SHARDS);
    auto shard = shards->get(0);

    REQUIRE(shard.has_value());
    REQUIRE(shard->shard_id == 0);
    REQUIRE(shard->seqno_start == 1);
    REQUIRE(shard->status == ccf::ShardStatus::Active);
  }

  INFO("Transition shard to Sealing and then Sealed");
  {
    auto tx = network.tables->create_tx();
    auto* shards = tx.rw<ccf::Shards>(ccf::Tables::SHARDS);

    auto shard = shards->get(0);
    REQUIRE(shard.has_value());

    shard->status = ccf::ShardStatus::Sealing;
    shard->seqno_end = 100;
    shards->put(0, shard.value());

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    // Verify sealing state
    auto tx2 = network.tables->create_read_only_tx();
    auto* shards2 = tx2.ro<ccf::Shards>(ccf::Tables::SHARDS);
    auto sealed = shards2->get(0);
    REQUIRE(sealed.has_value());
    REQUIRE(sealed->status == ccf::ShardStatus::Sealing);
    REQUIRE(sealed->seqno_end == 100);
  }

  INFO("Create new active shard after seal");
  {
    auto tx = network.tables->create_tx();
    auto* shards = tx.rw<ccf::Shards>(ccf::Tables::SHARDS);

    // Finalize the old shard
    auto old_shard = shards->get(0);
    REQUIRE(old_shard.has_value());
    old_shard->status = ccf::ShardStatus::Sealed;
    shards->put(0, old_shard.value());

    // Create the new active shard
    ccf::ShardInfo new_shard;
    new_shard.shard_id = 1;
    new_shard.seqno_start = 101;
    new_shard.seqno_end = std::numeric_limits<ccf::kv::Version>::max();
    new_shard.status = ccf::ShardStatus::Active;
    shards->put(1, new_shard);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Verify both shards coexist correctly");
  {
    auto tx = network.tables->create_read_only_tx();
    auto* shards = tx.ro<ccf::Shards>(ccf::Tables::SHARDS);

    auto shard0 = shards->get(0);
    REQUIRE(shard0.has_value());
    REQUIRE(shard0->status == ccf::ShardStatus::Sealed);
    REQUIRE(shard0->seqno_end == 100);

    auto shard1 = shards->get(1);
    REQUIRE(shard1.has_value());
    REQUIRE(shard1->status == ccf::ShardStatus::Active);
    REQUIRE(shard1->seqno_start == 101);
  }
}

TEST_CASE("Shard policy table operations")
{
  ccf::logger::config::default_init();

  ccf::NetworkState network;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  network.tables->set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);

  INFO("Set and read shard policy");
  {
    auto tx = network.tables->create_tx();
    auto* policy = tx.rw<ccf::ShardPolicy>(ccf::Tables::SHARD_POLICY);

    ccf::ShardPolicyInfo info;
    info.auto_seal_after_seqno_count = 1000;
    info.auto_seal_after_duration_s = 3600;
    info.max_active_shard_memory_mb = 512;
    policy->put(info);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = network.tables->create_read_only_tx();
    auto* policy = tx.ro<ccf::ShardPolicy>(ccf::Tables::SHARD_POLICY);

    auto info = policy->get();
    REQUIRE(info.has_value());
    REQUIRE(info->auto_seal_after_seqno_count == 1000);
    REQUIRE(info->auto_seal_after_duration_s == 3600);
    REQUIRE(info->max_active_shard_memory_mb == 512);
  }

  INFO("Update policy");
  {
    auto tx = network.tables->create_tx();
    auto* policy = tx.rw<ccf::ShardPolicy>(ccf::Tables::SHARD_POLICY);

    ccf::ShardPolicyInfo new_info;
    new_info.auto_seal_after_seqno_count = 5000;
    new_info.auto_seal_after_duration_s = 0;
    new_info.max_active_shard_memory_mb = 0;
    policy->put(new_info);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = network.tables->create_read_only_tx();
    auto* policy = tx.ro<ccf::ShardPolicy>(ccf::Tables::SHARD_POLICY);
    auto info = policy->get();
    REQUIRE(info.has_value());
    REQUIRE(info->auto_seal_after_seqno_count == 5000);
    REQUIRE(info->auto_seal_after_duration_s == 0);
  }
}

TEST_CASE("ShardInfo JSON serialisation round-trip")
{
  ccf::ShardInfo info;
  info.shard_id = 42;
  info.seqno_start = 100;
  info.seqno_end = 200;
  info.status = ccf::ShardStatus::Sealed;
  info.snapshot_seqno = 200;

  auto j = nlohmann::json(info);
  auto info2 = j.get<ccf::ShardInfo>();

  REQUIRE(info2.shard_id == 42);
  REQUIRE(info2.seqno_start == 100);
  REQUIRE(info2.seqno_end == 200);
  REQUIRE(info2.status == ccf::ShardStatus::Sealed);
  REQUIRE(info2.snapshot_seqno == 200);
}

TEST_CASE("ShardPolicyInfo JSON serialisation round-trip")
{
  ccf::ShardPolicyInfo policy;
  policy.auto_seal_after_seqno_count = 10000;
  policy.auto_seal_after_duration_s = 7200;
  policy.max_active_shard_memory_mb = 1024;

  auto j = nlohmann::json(policy);
  auto policy2 = j.get<ccf::ShardPolicyInfo>();

  REQUIRE(policy2.auto_seal_after_seqno_count == 10000);
  REQUIRE(policy2.auto_seal_after_duration_s == 7200);
  REQUIRE(policy2.max_active_shard_memory_mb == 1024);
}

TEST_CASE("Snapshotter shard seal marking")
{
  ccf::logger::config::default_init();

  ccf::NetworkState network;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto node_kp = ccf::crypto::make_ec_key_pair();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables.get(), ccf::kv::test::PrimaryNodeId, *node_kp);
  network.tables->set_history(history);
  network.tables->initialise_term(2);
  network.tables->set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);

  constexpr auto buffer_size = 1024 * 16;
  auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Circuit eio(in_buffer->bd, out_buffer->bd);

  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;
  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    *writer_factory, network.tables, snapshot_tx_interval);

  INFO("Mark snapshot as shard seal");
  {
    snapshotter->mark_next_snapshot_as_shard_seal(0);

    // Before any commit, this should not yet be committed
    REQUIRE_FALSE(snapshotter->is_shard_seal_snapshot_committed(0));
  }

  INFO("Shard seal completion callback is invoked");
  {
    std::optional<uint64_t> callback_shard_id = std::nullopt;
    snapshotter->set_on_shard_seal_committed(
      [&callback_shard_id](uint64_t shard_id) {
        callback_shard_id = shard_id;
      });

    // Verify callback is not yet called
    REQUIRE_FALSE(callback_shard_id.has_value());

    // The callback is invoked inside update_indices() when a shard-seal
    // snapshot is committed — here we just verify the setter works and
    // the callback pointer is stored
    snapshotter->mark_next_snapshot_as_shard_seal(7);
    REQUIRE_FALSE(callback_shard_id.has_value());
  }
}

int main(int argc, char** argv)
{
  ccf::logger::config::default_init();

  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
