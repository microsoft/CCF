// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/rpc/tx_status.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace ccf;

TEST_CASE("normal flow")
{
  constexpr auto target_view = 3;
  constexpr auto target_seqno = 10;

  // A tx id is unknown locally
  CHECK(evaluate_tx_status(3, 10, 0, 1, 0) == TxStatus::Unknown);

  // The tx id remains unknown while a node makes progress
  CHECK(evaluate_tx_status(3, 10, 0, 1, 1) == TxStatus::Unknown);
  CHECK(evaluate_tx_status(3, 10, 0, 1, 2) == TxStatus::Unknown);
  CHECK(evaluate_tx_status(3, 10, 0, 2, 3) == TxStatus::Unknown);
  CHECK(evaluate_tx_status(3, 10, 0, 2, 4) == TxStatus::Unknown);
  CHECK(evaluate_tx_status(3, 10, 0, 3, 5) == TxStatus::Unknown);
  CHECK(evaluate_tx_status(3, 10, 0, 3, 6) == TxStatus::Unknown);

  // Eventually the tx id becomes known locally
  CHECK(evaluate_tx_status(3, 10, 3, 3, 6) == TxStatus::Pending);

  // The tx id remains known while a node makes progress
  CHECK(evaluate_tx_status(3, 10, 3, 3, 7) == TxStatus::Pending);
  CHECK(evaluate_tx_status(3, 10, 3, 3, 8) == TxStatus::Pending);

  // Until either...
  {
    // ...the tx is globally committed...
    CHECK(evaluate_tx_status(3, 10, 3, 3, 9) == TxStatus::Pending);
    CHECK(evaluate_tx_status(3, 10, 3, 3, 10) == TxStatus::Committed);

    // The tx id remains permanently committed
    CHECK(evaluate_tx_status(3, 10, 3, 3, 11) == TxStatus::Committed);
    CHECK(evaluate_tx_status(3, 10, 3, 3, 12) == TxStatus::Committed);
    CHECK(evaluate_tx_status(3, 10, 3, 3, 13) == TxStatus::Committed);
    CHECK(evaluate_tx_status(3, 10, 3, 4, 14) == TxStatus::Committed);
    CHECK(evaluate_tx_status(3, 10, 3, 5, 15) == TxStatus::Committed);
  }
  // ...or...
  {
    // ...an election occurs, and the local tx is rolled back
    CHECK(evaluate_tx_status(3, 10, 0, 4, 9) == TxStatus::Invalid);

    // The tx id can never be committed
    CHECK(evaluate_tx_status(3, 10, 4, 4, 10) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 4, 4, 11) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 4, 4, 12) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 4, 4, 13) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 4, 4, 14) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 4, 5, 15) == TxStatus::Invalid);
  }
}

TEST_CASE("edge cases")
{
  {
    INFO("Unknown views");
    // Impossible: view for all global txs must be known
    // evaluate_tx_status(a, N, 0, b, >=N)
    CHECK_THROWS(evaluate_tx_status(3, 10, VIEW_UNKNOWN, 1, 10));
    CHECK_THROWS(evaluate_tx_status(3, 10, VIEW_UNKNOWN, 1, 11));
    CHECK_THROWS(evaluate_tx_status(3, 10, VIEW_UNKNOWN, 3, 10));
    CHECK_THROWS(evaluate_tx_status(3, 10, VIEW_UNKNOWN, 3, 11));
    CHECK_THROWS(evaluate_tx_status(3, 10, VIEW_UNKNOWN, 4, 10));
    CHECK_THROWS(evaluate_tx_status(3, 10, VIEW_UNKNOWN, 4, 11));
  }
  {
    INFO("seqno is known locally in an old view");

    // Node has heard about 2.10 locally, but has not committed to 10
    CHECK(evaluate_tx_status(3, 10, 2, 2, 8) == TxStatus::Unknown);
    // Impossible: remembering a later commit from an earlier view - should have
    // been rolled back
    // CHECK(evaluate_tx_status(3, 10, 2, 3, 8) == TxStatus::Unknown);

    // Node knows 2.10 (or later) has been committed - 3.10 is impossible
    CHECK(evaluate_tx_status(3, 10, 2, 2, 10) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 2, 2, 11) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 2, 3, 11) == TxStatus::Invalid);
    // Impossible: local doesn't match global
    // CHECK(evaluate_tx_status(3, 10, 2, 3, 10) == TxStatus::Invalid);
  }

  {
    INFO("Node is in a newer view");

    CHECK(evaluate_tx_status(3, 10, 0, 4, 8) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 4, 4, 8) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 4, 4, 10) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 4, 4, 11) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 4, 5, 11) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(3, 10, 4, 5, 12) == TxStatus::Invalid);
  }

  {
    INFO("Asking about future views");

    CHECK(evaluate_tx_status(100, 10, 0, 4, 8) == TxStatus::Unknown);
    CHECK(evaluate_tx_status(100, 10, 4, 4, 10) == TxStatus::Invalid);
    CHECK(evaluate_tx_status(100, 10, 4, 4, 12) == TxStatus::Invalid);
  }
}