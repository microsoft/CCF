// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/locking.h"
#include "tasks/basic_task.h"
#include "tasks/worker.h"

#include <barrier>
#include <csignal>
#include <doctest/doctest.h>
#include <new>
#include <regex>
#include <sys/resource.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace stacktrace_test
{
  struct CapturingLogger : public ccf::logger::AbstractLogger
  {
    ccf::ds::Mutex mutex;
    std::vector<std::pair<std::thread::id, std::string>> messages
      CCF_GUARDED_BY(mutex);

    void write(const ccf::logger::LogLine& line) override
    {
      ccf::ds::MutexGuard lock(mutex);
      messages.emplace_back(std::this_thread::get_id(), line.msg);
    }

    std::string take()
    {
      ccf::ds::MutexGuard lock(mutex);
      std::string result;
      const auto id = std::this_thread::get_id();
      std::erase_if(messages, [&](const auto& message) {
        if (message.first != id)
        {
          return false;
        }
        result += message.second + "\n";
        return true;
      });
      return result;
    }
  };

  struct CaptureLogs
  {
    CapturingLogger* logger;

    CaptureLogs()
    {
      auto owned = std::make_unique<CapturingLogger>();
      logger = owned.get();
      ccf::logger::config::loggers().push_back(std::move(owned));
    }

    ~CaptureLogs()
    {
      std::erase_if(ccf::logger::config::loggers(), [&](const auto& entry) {
        return entry.get() == logger;
      });
    }
  };

  __attribute__((noinline)) void throw_standard_exception()
  {
    throw std::runtime_error("throw-site failure");
  }

  __attribute__((noinline)) void throw_nonstandard_exception()
  {
    throw 42;
  }

  __attribute__((noinline)) void throw_at_depth(size_t remaining)
  {
    // Unwinding must visit each scope, including in optimised builds.
    struct KeepFrame
    {
      ~KeepFrame()
      {
        std::atomic_signal_fence(std::memory_order_seq_cst);
      }
    } frame;

    if (remaining == 0)
    {
      return throw_nonstandard_exception();
    }
    throw_at_depth(remaining - 1);
  }

  void check_throw_site(const std::string& output, const std::string& helper)
  {
    CHECK(output.contains("Stack trace:\n"));
    CHECK(output.contains(helper));
    CHECK_FALSE(output.contains("No throw-point stack trace available"));
    CHECK_FALSE(output.contains("dump_stacktrace("));
#ifdef CCF_STACKTRACE_TEST_DEBUG_INFO
    CHECK(std::regex_search(
      output,
      std::regex(helper + "[^\n]* at [^\n]*stacktrace.cpp:[1-9][0-9]*")));
#endif
  }

#ifdef CCF_STACKTRACE_USE_STD
  thread_local size_t allocations_to_fail = 0;
  thread_local size_t failed_allocations = 0;

  void fail_allocation_if_requested()
  {
    if (allocations_to_fail > 0)
    {
      --allocations_to_fail;
      ++failed_allocations;
      // This reenters __cxa_throw while the original capture is in progress.
      throw std::bad_alloc();
    }
  }
#endif
}

#ifdef CCF_STACKTRACE_USE_STD
extern "C" void* __real__Znwm(size_t size);

extern "C" void* __wrap__Znwm(size_t size)
{
  stacktrace_test::fail_allocation_if_requested();
  return __real__Znwm(size);
}

extern "C" void* __real__ZnwmRKSt9nothrow_t(
  size_t size, const std::nothrow_t& tag) noexcept;

extern "C" void* __wrap__ZnwmRKSt9nothrow_t(
  size_t size, const std::nothrow_t& tag) noexcept
{
  try
  {
    stacktrace_test::fail_allocation_if_requested();
  }
  catch (const std::bad_alloc&)
  {
    return nullptr;
  }
  return __real__ZnwmRKSt9nothrow_t(size, tag);
}
#endif

TEST_CASE("Throw-site trace consumption" * doctest::test_suite("stacktrace"))
{
  using namespace stacktrace_test;
  CaptureLogs logs;

  auto standard =
    ccf::tasks::make_basic_task(throw_standard_exception, "Standard");
  ccf::tasks::try_do_task(*standard, false);
  auto output = logs.logger->take();
  CHECK(
    output.contains("Standard task failed with exception: throw-site failure"));
  check_throw_site(output, "throw_standard_exception");

  ccf::tasks::dump_stacktrace("already consumed");
  output = logs.logger->take();
  CHECK(output.contains("No throw-point stack trace available"));
  CHECK_FALSE(output.contains("Stack trace:\n"));

  auto nonstandard =
    ccf::tasks::make_basic_task(throw_nonstandard_exception, "Nonstandard");
  ccf::tasks::try_do_task(*nonstandard, false);
  output = logs.logger->take();
  CHECK(output.contains("Nonstandard task failed with unknown exception"));
  check_throw_site(output, "throw_nonstandard_exception");
  CHECK_FALSE(output.contains("throw_standard_exception"));

  ccf::tasks::try_do_task(*standard, false);
  output = logs.logger->take();
  check_throw_site(output, "throw_standard_exception");
  CHECK_FALSE(output.contains("throw_nonstandard_exception"));
}

TEST_CASE("Throw-site thread isolation" * doctest::test_suite("stacktrace"))
{
  using namespace stacktrace_test;
  CaptureLogs logs;
  std::barrier captured(2);
  std::string first;
  std::string second;
  std::string fresh;

  std::thread a([&]() {
    ccf::tasks::dump_stacktrace("fresh thread");
    fresh = logs.logger->take();
    try
    {
      throw_standard_exception();
    }
    catch (const std::runtime_error&)
    {
      captured.arrive_and_wait();
      ccf::tasks::dump_stacktrace("first thread");
      first = logs.logger->take();
    }
  });
  std::thread b([&]() {
    try
    {
      throw_nonstandard_exception();
    }
    catch (int)
    {
      captured.arrive_and_wait();
      ccf::tasks::dump_stacktrace("second thread");
      second = logs.logger->take();
    }
  });
  a.join();
  b.join();

  CHECK(fresh.contains("No throw-point stack trace available"));
  check_throw_site(first, "throw_standard_exception");
  check_throw_site(second, "throw_nonstandard_exception");
  CHECK_FALSE(first.contains("throw_nonstandard_exception"));
  CHECK_FALSE(second.contains("throw_standard_exception"));
}

TEST_CASE("Throw-site bounded capture" * doctest::test_suite("stacktrace"))
{
  using namespace stacktrace_test;
  CaptureLogs logs;
  try
  {
    throw_at_depth(160);
  }
  catch (int value)
  {
    CHECK(value == 42);
    ccf::tasks::dump_stacktrace("deep throw");
  }
  const auto output = logs.logger->take();
  check_throw_site(output, "throw_nonstandard_exception");
  CHECK(output.contains("throw_at_depth"));
  size_t frames = 0;
  for (size_t offset = 0;
       (offset = output.find("  #", offset)) != std::string::npos;
       offset += 3)
  {
    ++frames;
  }
  CHECK(frames == 128);
  CHECK(output.contains("  #127: "));
  CHECK_FALSE(output.contains("  #128: "));
}

#ifdef CCF_STACKTRACE_USE_STD
TEST_CASE(
  "Throw-site allocation failure and reentrancy" *
  doctest::test_suite("stacktrace"))
{
  using namespace stacktrace_test;
  CaptureLogs logs;
  // Leave a previous trace unconsumed to check that a failed capture clears it.
  try
  {
    throw_standard_exception();
  }
  catch (const std::runtime_error&)
  {}

  const auto before = failed_allocations;
  int caught = 0;
  // A finite budget exposes recursive capture without exhausting the stack.
  allocations_to_fail = 8;
  try
  {
    throw_nonstandard_exception();
  }
  catch (int value)
  {
    caught = value;
  }
  const auto failure_was_injected = allocations_to_fail < 8;
  allocations_to_fail = 0;
  CHECK(failure_was_injected);
  CHECK(failed_allocations == before + 1);
  CHECK(caught == 42);
  ccf::tasks::dump_stacktrace("capture allocation failed");
  const auto output = logs.logger->take();
  CHECK(output.contains("No throw-point stack trace available"));
  CHECK_FALSE(output.contains("throw_standard_exception"));
  CHECK_FALSE(output.contains("bad_alloc"));

  auto task = ccf::tasks::make_basic_task(throw_nonstandard_exception);
  ccf::tasks::try_do_task(*task, false);
  check_throw_site(logs.logger->take(), "throw_nonstandard_exception");
}
#endif

TEST_CASE("Task abort on throw" * doctest::test_suite("stacktrace"))
{
  bool standard = true;
  SUBCASE("Standard exception") {}
  SUBCASE("Nonstandard exception")
  {
    standard = false;
  }
  const auto child = fork();
  REQUIRE(child >= 0);
  if (child == 0)
  {
    std::signal(SIGABRT, SIG_DFL);
    const rlimit no_core{0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0)
    {
      _exit(2);
    }
    auto task = ccf::tasks::make_basic_task(
      standard ? stacktrace_test::throw_standard_exception :
                 stacktrace_test::throw_nonstandard_exception);
    ccf::tasks::try_do_task(*task);
    _exit(1);
  }
  int status = 0;
  REQUIRE(waitpid(child, &status, 0) == child);
  REQUIRE(WIFSIGNALED(status));
  CHECK(WTERMSIG(status) == SIGABRT);
}
