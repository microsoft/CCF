// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/basic_task.h"
#include "tasks/job_board.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <pthread.h>

extern "C" int __real_pthread_mutex_unlock(pthread_mutex_t* mutex);

namespace
{
  // Capture the delayed-task mutex from an add_delayed_task() call, then
  // invoke a one-shot hook when that mutex is next released.
  struct UnlockControl
  {
    pthread_mutex_t* last_unlocked = nullptr;
    pthread_mutex_t* target = nullptr;
    void (*hook)(void*) = nullptr;
    void* hook_context = nullptr;
    bool capture = false;
    bool invoking_hook = false;
  };

  UnlockControl unlock_control;

  void start_unlock_capture()
  {
    unlock_control.last_unlocked = nullptr;
    unlock_control.capture = true;
  }

  pthread_mutex_t* finish_unlock_capture()
  {
    unlock_control.capture = false;
    return unlock_control.last_unlocked;
  }

  struct DelayedFollowUp
  {
    ccf::tasks::JobBoard board;
    size_t parent_calls = 0;
    size_t child_calls = 0;
    bool found_ready_parent = false;

    void run_ready_parent()
    {
      auto parent = board.get_task();
      found_ready_parent = parent != nullptr;
      if (parent != nullptr)
      {
        parent->do_task();
      }
    }
  };

  void run_ready_parent(void* context)
  {
    static_cast<DelayedFollowUp*>(context)->run_ready_parent();
  }
}

extern "C" int __wrap_pthread_mutex_unlock(pthread_mutex_t* mutex)
{
  const auto result = __real_pthread_mutex_unlock(mutex);
  if (result != 0 || unlock_control.invoking_hook)
  {
    return result;
  }

  if (unlock_control.capture)
  {
    unlock_control.last_unlocked = mutex;
  }

  if (mutex == unlock_control.target && unlock_control.hook != nullptr)
  {
    const auto hook = unlock_control.hook;
    auto* context = unlock_control.hook_context;
    unlock_control.hook = nullptr;
    unlock_control.invoking_hook = true;
    hook(context);
    unlock_control.invoking_hook = false;
  }

  return result;
}

TEST_CASE(
  "A fired timer schedules its follow-up against the new clock" *
  doctest::test_suite("delayed_tasks"))
{
  using namespace std::chrono_literals;

  DelayedFollowUp scenario;
  auto child =
    ccf::tasks::make_basic_task([&scenario]() { ++scenario.child_calls; });
  auto parent = ccf::tasks::make_basic_task([&scenario, child]() {
    ++scenario.parent_calls;
    scenario.board.add_delayed_task(child, 10ms);
  });

  start_unlock_capture();
  scenario.board.add_delayed_task(parent, 100ms);
  unlock_control.target = finish_unlock_capture();
  REQUIRE(unlock_control.target != nullptr);

  // Run the expired parent after tick() releases the delayed-task mutex but
  // before the ticker resumes, so its child observes the clock published by
  // that tick.
  unlock_control.hook = run_ready_parent;
  unlock_control.hook_context = &scenario;
  scenario.board.tick(100ms);

  REQUIRE(scenario.found_ready_parent);
  REQUIRE(scenario.parent_calls == 1);
  REQUIRE(scenario.child_calls == 0);
  REQUIRE(scenario.board.get_summary().pending_tasks == 0);

  scenario.board.tick(1ms);
  auto child_at_101ms = scenario.board.get_task();
  CHECK(child_at_101ms == nullptr);

  scenario.board.tick(9ms);
  auto child_at_110ms = scenario.board.get_task();
  REQUIRE(child_at_110ms != nullptr);
  child_at_110ms->do_task();
  CHECK(scenario.child_calls == 1);
  CHECK(scenario.board.get_summary().pending_tasks == 0);
}
