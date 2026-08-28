// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "consensus/aft/test/real_stack/fixture.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include <doctest/doctest.h>

// Sanity checks for RealStackFixture itself, with no concurrency at all:
// establishes that the real Store + real Aft + real MerkleTxHistory wiring
// behaves as expected before any interleaving is layered on top.

DOCTEST_TEST_CASE(
  "RealStackFixture wires a real Store, Aft, and MerkleTxHistory in "
  "agreement" *
  doctest::test_suite("real_stack_smoke"))
{
  ccf::kv::test::RealStackFixture fixture;

  DOCTEST_REQUIRE(fixture.raft->is_primary());
  DOCTEST_REQUIRE(fixture.store->current_txid() == ccf::TxID(0, 0));

  DOCTEST_INFO("Commit a handful of ordinary transactions");
  for (size_t i = 0; i < 5; ++i)
  {
    auto tx = fixture.store->create_tx();
    tx.rw(fixture.table)->put(i, i * 10);
    DOCTEST_REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto store_txid = fixture.store->current_txid();
  DOCTEST_CHECK(store_txid == ccf::TxID(fixture.initial_view, 5));
  DOCTEST_CHECK(fixture.raft->get_last_idx() == 5);
  DOCTEST_CHECK(fixture.history_txid() == store_txid);

  for (size_t i = 0; i < 5; ++i)
  {
    DOCTEST_CHECK(
      ccf::kv::test::read_value(*fixture.store, fixture.table, i) == i * 10);
  }

  DOCTEST_INFO(
    "Nothing is committed (in the raft sense) until a signature marks a "
    "point as globally committable - exactly as in production");
  DOCTEST_CHECK(fixture.raft->get_committed_seqno() == 0);

  DOCTEST_INFO("Emitting a real signature transaction advances commit_idx");
  const auto sig_txid = fixture.commit_signature();
  DOCTEST_CHECK(sig_txid == ccf::TxID(fixture.initial_view, 6));
  DOCTEST_CHECK(fixture.raft->get_committed_seqno() == 6);
  DOCTEST_CHECK(fixture.history_txid() == sig_txid);
}
