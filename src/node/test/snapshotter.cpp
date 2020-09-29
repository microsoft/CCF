// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/network_state.h"
#include "node/snapshotter.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>

TEST_CASE("Simple snapshots")
{
  ccf::NetworkState network;
  ringbuffer::Circuit eio(1024);
  std::unique_ptr<ringbuffer::WriterFactory> writer_factory =
    std::make_unique<ringbuffer::WriterFactory>(eio);

  size_t snapshot_tx_interval = 10;

  ccf::Snapshotter snapshotter(*writer_factory, network, snapshot_tx_interval);
}