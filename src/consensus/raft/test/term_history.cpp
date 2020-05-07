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
    INFO("Updating makes new indices known");
    history.update(1, 1);
    CHECK(history.term_at(0) == 1);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == TermHistory::InvalidTerm);
    CHECK(history.term_at(3) == TermHistory::InvalidTerm);
    CHECK(history.term_at(4) == TermHistory::InvalidTerm);

    history.update(2, 1);
    CHECK(history.term_at(0) == 1);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == 1);
    CHECK(history.term_at(3) == TermHistory::InvalidTerm);
    CHECK(history.term_at(4) == TermHistory::InvalidTerm);
  }

  {
    INFO("Term can advance too");
    history.update(3, 2);
    CHECK(history.term_at(0) == 1);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == 1);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == TermHistory::InvalidTerm);

    history.update(4, 3);
    CHECK(history.term_at(0) == 1);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == 1);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 3);
  }
}