// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "host/rpc_connections.h"

#include "ds/ring_buffer.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <chrono>
#include <doctest/doctest.h>
#include <memory>
#include <uv.h>

using namespace std::chrono_literals;

TEST_CASE("RPC connections retain their ID generator until UV close")
{
  constexpr size_t ringbuffer_size = 4096;
  ringbuffer::TestBuffer to_inside(ringbuffer_size);
  ringbuffer::TestBuffer from_inside(ringbuffer_size);
  ringbuffer::Circuit circuit(to_inside.bd, from_inside.bd);
  ringbuffer::WriterFactory writer_factory(circuit);

  auto id_gen = std::make_shared<asynchost::ConnIDGenerator>();
  std::weak_ptr<asynchost::ConnIDGenerator> weak_id_gen = id_gen;

  {
    asynchost::RPCConnections<asynchost::TCP> rpc(1s, writer_factory, id_gen);
    asynchost::RPCConnections<asynchost::UDP> rpc_udp(
      1s, writer_factory, id_gen);
  }

  // Destroying the proxies only schedules their timer close callbacks.
  id_gen.reset();
  CHECK_FALSE(weak_id_gen.expired());

  CHECK(uv_run(uv_default_loop(), UV_RUN_DEFAULT) == 0);
  CHECK(weak_id_gen.expired());
  CHECK(uv_loop_close(uv_default_loop()) == 0);
}
