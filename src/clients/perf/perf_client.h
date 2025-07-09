// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/cli_helper.h"

#include <CLI11/CLI11.hpp>
#include <chrono>
#include <fstream>

namespace client
{
  constexpr auto perf_summary = "perf_summary.csv";

  struct PerfOptions
  {
    std::string label;
    std::string pid_file;

    cli::ParsedAddress server_address;

    size_t max_writes_ahead = 0;

    PerfOptions(
      const std::string& default_label,
      const std::string& default_pid_file,
      CLI::App& app) :
      label(default_label),
      pid_file(fmt::format("{}.pid", default_pid_file))
    {
      // Enable config from file
      app.set_config("--config");

      app
        .add_option(
          "--label",
          label,
          fmt::format(
            "Identifier for this client, written to {}", perf_summary))
        ->capture_default_str();

      app
        .add_option(
          "--pid-file",
          pid_file,
          "Path to which the client PID will be written")
        ->capture_default_str();

      cli::add_address_option(
        app,
        server_address,
        "--rpc-address",
        "Remote node address to which requests should be sent")
        ->required(true);

      app
        .add_option(
          "--max-writes-ahead",
          max_writes_ahead,
          "How many transactions the client should send without waiting for "
          "responses. 0 will send all transactions before blocking for any "
          "responses, 1 will minimise latency by serially waiting for each "
          "transaction's response, other values may provide a balance between "
          "throughput and latency")
        ->capture_default_str();
    }
  };
}
