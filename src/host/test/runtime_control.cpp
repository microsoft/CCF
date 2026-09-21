// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "host/runtime_control.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

TEST_CASE("Runtime control" * doctest::test_suite("runtime_control"))
{
  size_t enclave_stop_request_count = 0;
  size_t ringbuffer_drain_count = 0;
  {
    const auto request_enclave_stop = [&enclave_stop_request_count]() {
      ++enclave_stop_request_count;
      return true;
    };
    const auto drain_ringbuffers = [&ringbuffer_drain_count]() {
      ++ringbuffer_drain_count;
    };
    asynchost::RuntimeControl runtime_control(
      request_enclave_stop, drain_ringbuffers);

    SUBCASE("`request_restart()` requests enclave shutdown")
    {
      runtime_control->request_restart();
      REQUIRE(enclave_stop_request_count == 1);
      REQUIRE(ringbuffer_drain_count == 0);
      REQUIRE_NOTHROW(runtime_control->throw_if_fatal_error());
    }

    SUBCASE("`report_stopped()` drains ringbuffers on the host loop")
    {
      runtime_control->report_stopped();
      uv_run(uv_default_loop(), UV_RUN_NOWAIT);
      REQUIRE(enclave_stop_request_count == 0);
      REQUIRE(ringbuffer_drain_count == 1);
      REQUIRE_NOTHROW(runtime_control->throw_if_fatal_error());
    }

    SUBCASE(
      "`report_fatal_error()` requests enclave shutdown and preserves the "
      "error")
    {
      runtime_control->report_fatal_error("join failed");
      runtime_control->report_stopped();
      uv_run(uv_default_loop(), UV_RUN_NOWAIT);
      REQUIRE(enclave_stop_request_count == 1);
      REQUIRE(ringbuffer_drain_count == 1);
      REQUIRE_THROWS_WITH_AS(
        runtime_control->throw_if_fatal_error(),
        "join failed",
        std::logic_error);
    }
  }

  uv_run(uv_default_loop(), UV_RUN_NOWAIT);
}
