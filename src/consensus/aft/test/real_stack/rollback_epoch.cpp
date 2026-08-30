// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "consensus/aft/test/real_stack/fixture.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include <doctest/doctest.h>
#include <optional>
#include <thread>

// Store::commit() decides whether a batch's chunk sizes are still wanted by
// comparing the rollback epoch it captured at allocation. These tests pin the
// two properties that makes sound: a rollback discards local writes only by
// truncating (which changes the epoch), and a rollback never moves chunk
// metadata forward past the Store.

using namespace ccf::kv::test;

DOCTEST_TEST_CASE(
  "A rollback never moves chunk metadata past the Store's own version" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  fixture.commit_signature();
  const auto version = fixture.store->current_version();
  DOCTEST_REQUIRE(fixture.chunker->current_version() == version);

  DOCTEST_SUBCASE("Rollback to the current version")
  {
    fixture.store->rollback(
      fixture.store->current_txid(), fixture.raft->get_view() + 1);
  }

  DOCTEST_SUBCASE("Rollback beyond the current version")
  {
    fixture.store->rollback(
      {fixture.raft->get_view(), version + 3}, fixture.raft->get_view() + 1);
  }

  DOCTEST_CHECK(fixture.store->current_version() == version);
  DOCTEST_CHECK(fixture.chunker->current_version() == version);
}

DOCTEST_TEST_CASE(
  "A rollback that discards a batch's writes always changes its epoch" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();

  // Pause a transaction once it has allocated a version and applied its
  // writes, so the rollback below genuinely races an in-flight batch.
  Checkpoint checkpoint("after local application");
  auto tx = fixture.store->create_tx();
  tx.rw(fixture.table)->put(2, 2);
  std::optional<ccf::kv::CommitResult> result;
  std::thread worker([&]() {
    result = tx.commit(
      ccf::empty_claims(), nullptr, checkpoint_post_apply_observer(checkpoint));
  });
  checkpoint.wait_until_paused();

  // The in-flight transaction holds a version above the rollback target, so
  // this must take the truncating path and move the rollback epoch on.
  const auto allocated = fixture.store->current_version();
  const auto epoch_before_rollback_is_initial =
    fixture.store->check_rollback_count(0);

  try
  {
    DOCTEST_REQUIRE(allocated > baseline_txid.seqno);
    DOCTEST_REQUIRE(epoch_before_rollback_is_initial);
    fixture.store->rollback(baseline_txid, fixture.raft->get_view() + 1);
  }
  catch (...)
  {
    checkpoint.release();
    worker.join();
    throw;
  }

  checkpoint.release();
  worker.join();

  DOCTEST_INFO("The truncating rollback moved the epoch on");
  DOCTEST_CHECK_FALSE(fixture.store->check_rollback_count(0));
  DOCTEST_REQUIRE(result.has_value());
  DOCTEST_CHECK(result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.chunker->current_version() == baseline_txid.seqno);
  DOCTEST_CHECK_FALSE(read_value(*fixture.store, fixture.table, 2).has_value());
}
