// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "consensus/aft/impl/state.h"

#include <doctest/doctest.h>

using namespace aft;

TEST_CASE("Advancing view history" * doctest::test_suite("viewhistory"))
{
  ViewHistory history;

  {
    INFO("Initial history is completely unknown");
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == ViewHistory::InvalidView);
    CHECK(history.view_at(2) == ViewHistory::InvalidView);
    CHECK(history.view_at(3) == ViewHistory::InvalidView);
    CHECK(history.view_at(4) == ViewHistory::InvalidView);

    CHECK(history.start_of_view(1) == ccf::kv::NoVersion);
    CHECK(history.end_of_view(1) == ccf::kv::NoVersion);
  }

  {
    INFO("Advancing index gives view for current and future indices");
    history.update(1, 1);
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == 1);
    CHECK(history.view_at(2) == 1);
    CHECK(history.view_at(3) == 1);
    CHECK(history.view_at(4) == 1);

    history.update(2, 1);
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == 1);
    CHECK(history.view_at(2) == 1);
    CHECK(history.view_at(3) == 1);
    CHECK(history.view_at(4) == 1);
  }

  {
    INFO("Advancing view increases view of affected indices");
    history.update(3, 2);
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == 1);
    CHECK(history.view_at(2) == 1);
    CHECK(history.view_at(3) == 2);
    CHECK(history.view_at(4) == 2);

    history.update(4, 3);
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == 1);
    CHECK(history.view_at(2) == 1);
    CHECK(history.view_at(3) == 2);
    CHECK(history.view_at(4) == 3);
  }

  {
    INFO("First and last entries in views");
    CHECK(history.start_of_view(1) == 1);
    CHECK(history.end_of_view(1) == 2);
    CHECK(history.start_of_view(2) == 3);
    CHECK(history.end_of_view(2) == 3);
    CHECK(history.start_of_view(3) == 4);
    CHECK(history.end_of_view(3) == ccf::kv::NoVersion);
    CHECK(history.start_of_view(4) == ccf::kv::NoVersion);
    CHECK(history.end_of_view(4) == ccf::kv::NoVersion);
  }
}

TEST_CASE("Edge case view histories" * doctest::test_suite("viewhistory"))
{
  {
    INFO("Index skips leave unknown indices");
    ViewHistory history;
    history.update(3, 1);
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == ViewHistory::InvalidView);
    CHECK(history.view_at(2) == ViewHistory::InvalidView);
    CHECK(history.view_at(3) == 1);
    CHECK(history.view_at(4) == 1);
  }

  {
    INFO("View skips advance to given view");
    ViewHistory history;
    history.update(3, 2);
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == ViewHistory::InvalidView);
    CHECK(history.view_at(2) == ViewHistory::InvalidView);
    CHECK(history.view_at(3) == 2);
    CHECK(history.view_at(4) == 2);
  }

  {
    INFO(
      "Subsequent calls on same view must not move backward from view start");
    ViewHistory history;
    history.update(2, 2);
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == ViewHistory::InvalidView);
    CHECK(history.view_at(2) == 2);
    CHECK(history.view_at(3) == 2);
    CHECK(history.view_at(4) == 2);

    CHECK_NOTHROW(history.update(2, 2));
    CHECK_NOTHROW(history.update(3, 2));
    CHECK_NOTHROW(history.update(2, 2));
    CHECK_NOTHROW(history.update(4, 2));
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == ViewHistory::InvalidView);
    CHECK(history.view_at(2) == 2);
    CHECK(history.view_at(3) == 2);
    CHECK(history.view_at(4) == 2);

    CHECK_THROWS(history.update(1, 2));
  }

  {
    INFO("Highest matching view is returned");
    ViewHistory history;
    history.update(2, 2);
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == ViewHistory::InvalidView);
    CHECK(history.view_at(2) == 2);
    CHECK(history.view_at(3) == 2);
    CHECK(history.view_at(4) == 2);

    history.update(2, 4);
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == ViewHistory::InvalidView);
    CHECK(history.view_at(2) == 4);
    CHECK(history.view_at(3) == 4);
    CHECK(history.view_at(4) == 4);

    history.update(2, 3);
    CHECK(history.view_at(0) == ViewHistory::InvalidView);
    CHECK(history.view_at(1) == ViewHistory::InvalidView);
    CHECK(history.view_at(2) == 4);
    CHECK(history.view_at(3) == 4);
    CHECK(history.view_at(4) == 4);

    CHECK(history.start_of_view(4) == 2);
    CHECK(history.end_of_view(4) == ccf::kv::NoVersion);

    CHECK(history.start_of_view(1) == ccf::kv::NoVersion);
    CHECK(history.end_of_view(1) == ccf::kv::NoVersion);
    CHECK(history.start_of_view(2) == ccf::kv::NoVersion);
    CHECK(history.end_of_view(2) == ccf::kv::NoVersion);
    CHECK(history.start_of_view(3) == ccf::kv::NoVersion);
    CHECK(history.end_of_view(3) == ccf::kv::NoVersion);
  }
}

TEST_CASE("Initialised view histories" * doctest::test_suite("viewhistory"))
{
  {
    INFO("Initialise validates the given view history");
    ViewHistory history;
    CHECK_NOTHROW(history.initialise({}));
    CHECK_NOTHROW(history.initialise({1}));
    CHECK_NOTHROW(history.initialise({2}));
    CHECK_NOTHROW(history.initialise({1, 2}));
    CHECK_NOTHROW(history.initialise({2, 2}));
    CHECK_NOTHROW(history.initialise({2, 4, 4, 10}));

    CHECK(history.start_of_view(1) == 2);
    CHECK(history.end_of_view(1) == 3);
    CHECK(history.start_of_view(2) == ccf::kv::NoVersion);
    CHECK(history.end_of_view(2) == ccf::kv::NoVersion);
    CHECK(history.start_of_view(3) == 4);
    CHECK(history.end_of_view(3) == 9);
    CHECK(history.start_of_view(4) == 10);
    CHECK(history.end_of_view(4) == ccf::kv::NoVersion);

    CHECK_THROWS(history.initialise({2, 1}));
    CHECK_THROWS(history.initialise({1, 2, 1}));
    CHECK_THROWS(history.initialise({2, 4, 4, 10, 9}));
  }

  {
    INFO("Initialise overwrites view history");
    ViewHistory history;
    history.update(5, 1);
    history.update(10, 2);
    history.update(20, 3);
    CHECK(history.view_at(4) == ViewHistory::InvalidView);
    CHECK(history.view_at(8) == 1);
    CHECK(history.view_at(19) == 2);
    CHECK(history.view_at(20) == 3);

    history.initialise({6});
    CHECK(history.view_at(4) == ViewHistory::InvalidView);
    CHECK(history.view_at(8) == 1);
    CHECK(history.view_at(19) == 1);
    CHECK(history.view_at(20) == 1);

    history.initialise({3, 3, 3, 5, 6, 12});
    CHECK(history.view_at(4) == 3);
    CHECK(history.view_at(8) == 5);
    CHECK(history.view_at(19) == 6);
    CHECK(history.view_at(20) == 6);

    CHECK(history.start_of_view(1) == ccf::kv::NoVersion);
    CHECK(history.end_of_view(1) == ccf::kv::NoVersion);
    CHECK(history.start_of_view(3) == 3);
    CHECK(history.end_of_view(3) == 4);
    CHECK(history.start_of_view(4) == 5);
    CHECK(history.end_of_view(4) == 5);
    CHECK(history.start_of_view(5) == 6);
    CHECK(history.end_of_view(5) == 11);
    CHECK(history.start_of_view(6) == 12);
    CHECK(history.end_of_view(6) == ccf::kv::NoVersion);
  }
}

TEST_CASE(
  "Retrieving view history up to a specific version" *
  doctest::test_suite("viewhistory"))
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

    REQUIRE(history.get_history_until(ccf::kv::NoVersion).size() == 0);
    REQUIRE(history.get_history_until(1) == std::vector<ccf::kv::Version>({1}));
    REQUIRE(
      history.get_history_until(2) == std::vector<ccf::kv::Version>({1, 2}));
    REQUIRE(
      history.get_history_until(3) == std::vector<ccf::kv::Version>({1, 2}));
    REQUIRE(
      history.get_history_until(4) == std::vector<ccf::kv::Version>({1, 2}));
    REQUIRE(
      history.get_history_until(5) ==
      std::vector<ccf::kv::Version>({1, 2, 5, 5}));
    REQUIRE(
      history.get_history_until(9) ==
      std::vector<ccf::kv::Version>({1, 2, 5, 5}));
    REQUIRE(
      history.get_history_until(10) ==
      std::vector<ccf::kv::Version>({1, 2, 5, 5, 10}));
    REQUIRE(
      history.get_history_until(11) ==
      std::vector<ccf::kv::Version>({1, 2, 5, 5, 10}));
    REQUIRE(
      history.get_history_until() ==
      std::vector<ccf::kv::Version>({1, 2, 5, 5, 10}));
  }
}
