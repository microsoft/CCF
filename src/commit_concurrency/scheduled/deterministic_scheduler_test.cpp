// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/pal/locking.h"
#include "commit_concurrency/scheduled/deterministic_scheduler.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include <algorithm>
#include <doctest/doctest.h>
#include <fmt/format.h>

using namespace ccf::kv::test;

DOCTEST_TEST_CASE(
  "A single actor with no contention explores exactly one schedule" *
  doctest::test_suite("deterministic_scheduler"))
{
  size_t counter = 0;
  const auto explored =
    explore_all_interleavings(1, [&]() -> std::vector<std::function<void()>> {
      counter = 0;
      return {[&]() { counter = 1; }};
    });
  DOCTEST_CHECK(explored == 1);
  DOCTEST_CHECK(counter == 1);
}

// A real ccf::pal::Mutex lock()/unlock() is intercepted at link time (see
// src/commit_concurrency/scheduled/pthread_mutex_wrap.cpp) rather than
// via a distinct C++ type, so nothing here stops a future change (e.g.
// dropping the -Wl,--wrap=... flags in CMakeLists.txt, or a libc/compiler
// change that stops emitting a plain pthread_mutex_lock call) from
// silently making that interception a no-op: every actor's real lock and
// unlock would then just succeed immediately as ordinary OS-level
// locking, with DeterministicScheduler never told about any of it. Every
// other test in this file could plausibly still pass in that scenario
// (e.g. "explored > 1" could, in principle, come from yield_point() calls
// alone) - this test instead asserts, explicitly and unambiguously, that
// a real lock/unlock actually produced the three events before_lock()/
// after_unlock() are documented to report, which is only possible if
// interception genuinely engaged.
DOCTEST_TEST_CASE(
  "Smoke test: a real ccf::pal::Mutex lock/unlock is genuinely intercepted, "
  "not silently left as real, untracked OS-level locking" *
  doctest::test_suite("deterministic_scheduler"))
{
  ccf::pal::Mutex mtx;
  explore_all_interleavings(
    1,
    [&]() -> std::vector<std::function<void()>> {
      return {[&]() { std::lock_guard<ccf::pal::Mutex> guard(mtx); }};
    },
    [&](const DeterministicScheduler& scheduler) {
      const auto& path = scheduler.decision_path();
      const auto has_kind = [&](ActorEventKind kind) {
        return std::any_of(path.begin(), path.end(), [&](const auto& d) {
          return d.trigger_event.kind == kind;
        });
      };
      DOCTEST_CHECK(has_kind(ActorEventKind::Requested));
      DOCTEST_CHECK(has_kind(ActorEventKind::Acquired));
      DOCTEST_CHECK(has_kind(ActorEventKind::Released));
    });
}

DOCTEST_TEST_CASE(
  "Two actors each incrementing a shared counter under a shared lock reach "
  "the same, correct total on every explored interleaving" *
  doctest::test_suite("deterministic_scheduler"))
{
  size_t counter = 0;
  ccf::pal::Mutex mtx;

  const auto explored = explore_all_interleavings(
    2,
    [&]() -> std::vector<std::function<void()>> {
      counter = 0;
      return {
        [&]() {
          std::lock_guard<ccf::pal::Mutex> guard(mtx);
          counter++;
        },
        [&]() {
          std::lock_guard<ccf::pal::Mutex> guard(mtx);
          counter++;
        }};
    },
    [&](const DeterministicScheduler&) { DOCTEST_CHECK(counter == 2); });

  DOCTEST_INFO(fmt::format("Explored {} schedules", explored));
  DOCTEST_CHECK(explored > 1);
}

namespace
{
  // A deliberately racy "lazy initialisation" pattern: each actor reads
  // whether initialisation has already happened, and if not, performs it -
  // but the read and the (potential) write are two separate critical
  // sections rather than one, leaving a gap in which another actor can
  // run. run_actor_with_gap() also marks that gap with yield_point(), on
  // top of the decision points already made at each lock/unlock, purely
  // to give it an explicit, named label in describe()'s output.
  struct LazyInitScenario
  {
    bool initialised = false;
    size_t init_count = 0;
    ccf::pal::Mutex mtx;

    void run_actor_with_gap()
    {
      bool already_done;
      {
        std::lock_guard<ccf::pal::Mutex> guard(mtx);
        already_done = initialised;
      }
      yield_point("checked initialised flag, about to act on it");
      if (!already_done)
      {
        std::lock_guard<ccf::pal::Mutex> guard(mtx);
        initialised = true;
        init_count++;
      }
    }

    void run_actor_without_gap()
    {
      std::lock_guard<ccf::pal::Mutex> guard(mtx);
      if (!initialised)
      {
        initialised = true;
        init_count++;
      }
    }
  };
}

DOCTEST_TEST_CASE(
  "A lazy-init race across two separate critical sections is caught on at "
  "least one, but not all, explored interleavings, and describe() explains "
  "the first such schedule" *
  doctest::test_suite("deterministic_scheduler"))
{
  std::unique_ptr<LazyInitScenario> scenario;
  size_t schedules_with_double_init = 0;
  size_t schedules_with_single_init = 0;
  std::string first_bad_schedule_description;

  const auto explored = explore_all_interleavings(
    2,
    [&]() -> std::vector<std::function<void()>> {
      scenario = std::make_unique<LazyInitScenario>();
      return {
        [&]() { scenario->run_actor_with_gap(); },
        [&]() { scenario->run_actor_with_gap(); }};
    },
    [&](const DeterministicScheduler& scheduler) {
      if (scenario->init_count > 1)
      {
        schedules_with_double_init++;
        if (first_bad_schedule_description.empty())
        {
          first_bad_schedule_description = scheduler.describe();
        }
      }
      else
      {
        schedules_with_single_init++;
      }
    },
    100000,
    {"first", "second"});

  DOCTEST_INFO(fmt::format(
    "Explored {} schedules: {} with a double init, {} with a single init",
    explored,
    schedules_with_double_init,
    schedules_with_single_init));
  DOCTEST_CHECK(explored > 1);
  DOCTEST_CHECK(schedules_with_double_init > 0);
  DOCTEST_CHECK(schedules_with_single_init > 0);

  DOCTEST_INFO(
    "describe() names the two actors as given, and shows both taking "
    "their post-check action label before either one wins the race");
  DOCTEST_CHECK(
    first_bad_schedule_description.find("first") != std::string::npos);
  DOCTEST_CHECK(
    first_bad_schedule_description.find("second") != std::string::npos);
  DOCTEST_CHECK(
    first_bad_schedule_description.find(
      "checked initialised flag, about to act on it") != std::string::npos);
}

DOCTEST_TEST_CASE(
  "Collapsing the check and the write into one critical section removes "
  "the race on every explored interleaving" *
  doctest::test_suite("deterministic_scheduler"))
{
  std::unique_ptr<LazyInitScenario> scenario;
  size_t schedules_with_double_init = 0;

  const auto explored = explore_all_interleavings(
    2,
    [&]() -> std::vector<std::function<void()>> {
      scenario = std::make_unique<LazyInitScenario>();
      return {
        [&]() { scenario->run_actor_without_gap(); },
        [&]() { scenario->run_actor_without_gap(); }};
    },
    [&](const DeterministicScheduler&) {
      if (scenario->init_count > 1)
      {
        schedules_with_double_init++;
      }
    });

  DOCTEST_INFO(fmt::format("Explored {} schedules", explored));
  DOCTEST_CHECK(explored > 1);
  DOCTEST_CHECK(schedules_with_double_init == 0);
}

DOCTEST_TEST_CASE(
  "Random sampling of the same racy scenario reliably hits the bug too, "
  "and is exactly reproducible from its seed" *
  doctest::test_suite("deterministic_scheduler"))
{
  std::unique_ptr<LazyInitScenario> scenario;
  auto make_run = [&]() -> std::vector<std::function<void()>> {
    scenario = std::make_unique<LazyInitScenario>();
    return {
      [&]() { scenario->run_actor_with_gap(); },
      [&]() { scenario->run_actor_with_gap(); }};
  };

  size_t schedules_with_double_init = 0;
  explore_random_interleavings(
    2,
    make_run,
    [&](const DeterministicScheduler&) {
      if (scenario->init_count > 1)
      {
        schedules_with_double_init++;
      }
    },
    50,
    42);
  DOCTEST_INFO(fmt::format(
    "{} of 50 randomly sampled schedules hit the double-init bug",
    schedules_with_double_init));
  DOCTEST_CHECK(schedules_with_double_init > 0);

  // Same seed, same 50 samples: an exact repeat, not just "close enough".
  size_t schedules_with_double_init_repeat = 0;
  explore_random_interleavings(
    2,
    make_run,
    [&](const DeterministicScheduler&) {
      if (scenario->init_count > 1)
      {
        schedules_with_double_init_repeat++;
      }
    },
    50,
    42);
  DOCTEST_CHECK(
    schedules_with_double_init_repeat == schedules_with_double_init);
}

DOCTEST_TEST_CASE(
  "estimate_schedule_count reports exactly one schedule for a scenario "
  "with no branching, and a plausible order of magnitude for one that has "
  "some" *
  doctest::test_suite("deterministic_scheduler"))
{
  {
    size_t counter = 0;
    const auto estimates =
      estimate_schedule_count(1, [&]() -> std::vector<std::function<void()>> {
        counter = 0;
        return {[&]() { counter = 1; }};
      });
    for (const auto estimate : estimates)
    {
      DOCTEST_CHECK(estimate == 1.0);
    }
  }

  {
    // The exhaustive test above finds exactly 10968 schedules for this
    // scenario now that every lock request/acquire/release (not just
    // contended acquisitions) is a decision point - a random-walk
    // estimate is not expected to land on that exactly, but should be in
    // the right ballpark rather than off by orders of magnitude.
    std::unique_ptr<LazyInitScenario> scenario;
    const auto estimates =
      estimate_schedule_count(2, [&]() -> std::vector<std::function<void()>> {
        scenario = std::make_unique<LazyInitScenario>();
        return {
          [&]() { scenario->run_actor_with_gap(); },
          [&]() { scenario->run_actor_with_gap(); }};
      });
    double min_estimate = *std::min_element(estimates.begin(), estimates.end());
    double max_estimate = *std::max_element(estimates.begin(), estimates.end());
    DOCTEST_INFO(fmt::format(
      "Estimates ranged from {} to {} (true count is 10968)",
      min_estimate,
      max_estimate));
    DOCTEST_CHECK(min_estimate >= 1.0);
    DOCTEST_CHECK(max_estimate <= 200000.0);
  }
}
