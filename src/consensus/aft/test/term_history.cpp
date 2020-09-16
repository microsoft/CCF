// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "consensus/aft/raft.h"

#include <doctest/doctest.h>

using namespace aft;

TEST_CASE("Advancing term history" * doctest::test_suite("termhistory"))
{
  ViewHistory history;

  {
    INFO("Initial history is completely unknown");
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == ViewHistory::InvalidView);
    CHECK(history.term_at(2) == ViewHistory::InvalidView);
    CHECK(history.term_at(3) == ViewHistory::InvalidView);
    CHECK(history.term_at(4) == ViewHistory::InvalidView);
  }

  {
    INFO("Advancing index gives term for current and future indices");
    history.update(1, 1);
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == 1);
    CHECK(history.term_at(3) == 1);
    CHECK(history.term_at(4) == 1);

    history.update(2, 1);
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == 1);
    CHECK(history.term_at(3) == 1);
    CHECK(history.term_at(4) == 1);
  }

  {
    INFO("Advancing term increases term of affected indices");
    history.update(3, 2);
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == 1);
    CHECK(history.term_at(2) == 1);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 2);

    history.update(4, 3);
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
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
    ViewHistory history;
    history.update(3, 1);
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == ViewHistory::InvalidView);
    CHECK(history.term_at(2) == ViewHistory::InvalidView);
    CHECK(history.term_at(3) == 1);
    CHECK(history.term_at(4) == 1);
  }

  {
    INFO("Term skips advance to given term");
    ViewHistory history;
    history.update(3, 2);
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == ViewHistory::InvalidView);
    CHECK(history.term_at(2) == ViewHistory::InvalidView);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 2);
  }

  {
    INFO(
      "Subsequent calls on same term must not move backward from term start");
    ViewHistory history;
    history.update(2, 2);
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == ViewHistory::InvalidView);
    CHECK(history.term_at(2) == 2);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 2);

    CHECK_NOTHROW(history.update(2, 2));
    CHECK_NOTHROW(history.update(3, 2));
    CHECK_NOTHROW(history.update(2, 2));
    CHECK_NOTHROW(history.update(4, 2));
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == ViewHistory::InvalidView);
    CHECK(history.term_at(2) == 2);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 2);

    CHECK_THROWS(history.update(1, 2));
  }

  {
    INFO("Highest matching term is returned");
    ViewHistory history;
    history.update(2, 2);
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == ViewHistory::InvalidView);
    CHECK(history.term_at(2) == 2);
    CHECK(history.term_at(3) == 2);
    CHECK(history.term_at(4) == 2);

    history.update(2, 4);
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == ViewHistory::InvalidView);
    CHECK(history.term_at(2) == 4);
    CHECK(history.term_at(3) == 4);
    CHECK(history.term_at(4) == 4);

    history.update(2, 3);
    CHECK(history.term_at(0) == ViewHistory::InvalidView);
    CHECK(history.term_at(1) == ViewHistory::InvalidView);
    CHECK(history.term_at(2) == 4);
    CHECK(history.term_at(3) == 4);
    CHECK(history.term_at(4) == 4);
  }
}

TEST_CASE("Initialised term histories" * doctest::test_suite("termhistory"))
{
  {
    INFO("Initialise validates the given term history");
    ViewHistory history;
    CHECK_NOTHROW(history.initialise({}));
    CHECK_NOTHROW(history.initialise({1}));
    CHECK_NOTHROW(history.initialise({2}));
    CHECK_NOTHROW(history.initialise({1, 2}));
    CHECK_NOTHROW(history.initialise({2, 2}));
    CHECK_NOTHROW(history.initialise({2, 4, 4, 10}));
    CHECK_THROWS(history.initialise({2, 1}));
    CHECK_THROWS(history.initialise({1, 2, 1}));
    CHECK_THROWS(history.initialise({2, 4, 4, 10, 9}));
  }

  {
    INFO("Initialise overwrites term history");
    ViewHistory history;
    history.update(5, 1);
    history.update(10, 2);
    history.update(20, 3);
    CHECK(history.term_at(4) == ViewHistory::InvalidView);
    CHECK(history.term_at(8) == 1);
    CHECK(history.term_at(19) == 2);
    CHECK(history.term_at(20) == 3);

    history.initialise({6});
    CHECK(history.term_at(4) == ViewHistory::InvalidView);
    CHECK(history.term_at(8) == 1);
    CHECK(history.term_at(19) == 1);
    CHECK(history.term_at(20) == 1);

    history.initialise({3, 3, 3, 5, 6, 12});
    CHECK(history.term_at(4) == 3);
    CHECK(history.term_at(8) == 5);
    CHECK(history.term_at(19) == 6);
    CHECK(history.term_at(20) == 6);
  }
}

TEST_CASE(
  "Retrieving view history up to a specific version" *
  doctest::test_suite("termhistory"))
{
  ViewHistory history;

  {
    INFO("Populate view history");
    history.update(1, 1);
    history.update(2, 2);
    history.update(5, 3);
    history.update(5, 4);
    history.update(10, 5);
  }

  {
    INFO("Test that view history is correct");

    REQUIRE(history.get_history_until(kv::NoVersion).size() == 0);
    REQUIRE(history.get_history_until(1) == std::vector<kv::Version>({1}));
    REQUIRE(history.get_history_until(2) == std::vector<kv::Version>({1, 2}));
    REQUIRE(history.get_history_until(3) == std::vector<kv::Version>({1, 2}));
    REQUIRE(history.get_history_until(4) == std::vector<kv::Version>({1, 2}));
    REQUIRE(
      history.get_history_until(5) == std::vector<kv::Version>({1, 2, 5, 5}));
    REQUIRE(
      history.get_history_until(9) == std::vector<kv::Version>({1, 2, 5, 5}));
    REQUIRE(
      history.get_history_until(10) ==
      std::vector<kv::Version>({1, 2, 5, 5, 10}));
    REQUIRE(
      history.get_history_until(11) ==
      std::vector<kv::Version>({1, 2, 5, 5, 10}));
    REQUIRE(
      history.get_history_until() ==
      std::vector<kv::Version>({1, 2, 5, 5, 10}));
  }
}
