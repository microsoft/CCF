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
    /// Options set from command line
    ///@{
    std::string label; //< Default set in constructor
    std::string pid_file; //< Default set in constructor

    cli::ParsedAddress server_address;
    std::string cert_file, key_file, ca_file, verification_file, bearer_token;

    size_t num_transactions = 10000;
    size_t thread_count = 1;
    size_t session_count = 1;
    size_t max_writes_ahead = 0;
    size_t latency_rounds = 1;
    size_t generator_seed = 42u;
    size_t transactions_per_s = 0;

    bool sign = false;
    bool no_create = false;
    bool no_wait = false;
    bool write_tx_times = false;
    bool randomise = false;
    bool check_responses = false;
    bool relax_commit_target = false;
    ///@}

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

      // Connection details
      cli::add_address_option(
        app,
        server_address,
        "--rpc-address",
        "Remote node JSON RPC address to which requests should be sent")
        ->required(true);

      app.add_option("--cert", cert_file)
        ->required(true)
        ->check(CLI::ExistingFile);
      app.add_option("--pk", key_file)
        ->required(true)
        ->check(CLI::ExistingFile);
      app.add_option("--ca", ca_file)->required(true)->check(CLI::ExistingFile);
      app.add_option("--bearer-token", bearer_token)->required(false);

      app
        .add_option(
          "--verify",
          verification_file,
          "Verify results against expectation, specified in file")
        ->required(false)
        ->check(CLI::ExistingFile);
      app.add_option("--generator-seed", generator_seed);

      app.add_option(
        "--transaction-rate",
        transactions_per_s,
        "The number of transactions per second to send");

      // Transaction counts and batching details
      app
        .add_option(
          "--transactions",
          num_transactions,
          "The basic number of transactions to send (will actually send this "
          "many for each thread, in each session)")
        ->capture_default_str();
      app.add_option("-t,--threads", thread_count)->capture_default_str();
      app.add_option("-s,--sessions", session_count)->capture_default_str();
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

      app.add_option("--latency-rounds", latency_rounds)->capture_default_str();

      // Boolean flags
      app.add_flag("--sign", sign, "Send client-signed transactions")
        ->capture_default_str();
      app
        .add_flag("--no-create", no_create, "Skip creation/setup transactions")
        ->capture_default_str();
      app
        .add_flag(
          "--no-wait",
          no_wait,
          "Don't wait for transactions to be globally committed")
        ->capture_default_str();
      app
        .add_flag(
          "--write-tx-times",
          write_tx_times,
          "Write tx sent and received times to csv")
        ->capture_default_str();
      app
        .add_flag(
          "--randomise",
          randomise,
          "Use non-deterministically random transaction contents each run")
        ->capture_default_str();
      app
        .add_flag(
          "--check-responses",
          check_responses,
          "Check every JSON response for errors. Potentially slow")
        ->capture_default_str();
    }
  };
}
