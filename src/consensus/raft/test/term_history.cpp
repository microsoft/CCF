// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "consensus/raft/raft.h"

#include <doctest/doctest.h>

using namespace raft;

TEST_CASE("Advancing term history" * doctest::test_suite("termhistory"))
{
  TermHistory history;

  {
    INFO("Initial history is completely unknown");
    CHECK(history.term_at(0) == TermHistory::InvalidTerm);
    CHECK(history.term_at(1) == TermHistory::InvalidTerm);
    CHECK(history.term_at(2) == TermHistory::InvalidTerm);
    CHECK(history.term_at(3) == TermHistory::InvalidTerm);
    CHECK(history.term_at(4) == TermHistory::InvalidTerm);
  }

  {
    INFO("Advancing index gives term for current and future indices");
    history.update(1, 1);
    CHECK(history.term_at(0) == TermHistory::InvalidTerm);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == 1);
    CHECK(history.term_at(3) == 1);
    CHECK(history.term_at(4) == 1);

    history.update(2, 1);
    CHECK(history.term_at(0) == TermHistory::InvalidTerm);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == 1);
    CHECK(history.term_at(3) == 1);
    CHECK(history.term_at(4) == 1);
  }

  {
    INFO("Advancing term increases term of affected indices");
    history.update(3, 2);
    CHECK(history.term_at(0) == TermHistory::InvalidTerm);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == 1);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 2);

    history.update(4, 3);
    CHECK(history.term_at(0) == TermHistory::InvalidTerm);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == 1);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 3);
  }
}

TEST_CASE("Edge case term histories" * doctest::test_suite("termhistory"))
{
  {
    INFO("Index skips leave unknown indices");
    TermHistory history;
    history.update(3, 1);
    CHECK(history.term_at(0) == TermHistory::InvalidTerm);
    CHECK(history.term_at(1) == TermHistory::InvalidTerm);
    CHECK(history.term_at(2) == TermHistory::InvalidTerm);
    CHECK(history.term_at(3) == 1);
    CHECK(history.term_at(4) == 1);
  }

  {
    INFO("Term skips advance to given term");
    TermHistory history;
    history.update(3, 2);
    CHECK(history.term_at(0) == TermHistory::InvalidTerm);
    CHECK(history.term_at(1) == TermHistory::InvalidTerm);
    CHECK(history.term_at(2) == TermHistory::InvalidTerm);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 2);
  }

  {
    INFO("Update is only applied for the first call per-term");
    TermHistory history;
    history.update(2, 2);
    CHECK(history.term_at(0) == TermHistory::InvalidTerm);
    CHECK(history.term_at(1) == TermHistory::InvalidTerm);
    CHECK(history.term_at(2) == 2);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 2);

    history.update(4, 2);
    CHECK(history.term_at(0) == TermHistory::InvalidTerm);
    CHECK(history.term_at(1) == TermHistory::InvalidTerm);
    CHECK(history.term_at(2) == 2);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 2);

    history.update(1, 2);
    CHECK(history.term_at(0) == TermHistory::InvalidTerm);
    CHECK(history.term_at(1) == TermHistory::InvalidTerm);
    CHECK(history.term_at(2) == 2);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 2);
  }
}

TEST_CASE("Initialised term histories" * doctest::test_suite("termhistory")) {}