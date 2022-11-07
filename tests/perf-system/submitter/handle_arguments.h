// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/logger.h"

#include <CLI11/CLI11.hpp>
#include <iostream>

class ArgumentParser
{
public:
  std::string label; //< Default set in constructor
  std::string pid_file; //< Default set in constructor

  std::string cert;
  std::string key;
  std::string rootCa;
  std::string server_address = "127.0.0.1:8000";
  std::string send_filepath = "../tests/perf-system/submitter/cpp_send.parquet";
  std::string response_filepath =
    "../tests/perf-system/submitter/cpp_respond.parquet";
  std::string generator_filepath =
    "../tests/perf-system/generator/requests.parquet";
  bool pipeline = false;

  ArgumentParser(
    const std::string& default_label,
    const std::string& default_pid_file,
    CLI::App& app) :
    label(default_label),
    pid_file(fmt::format("{}.pid", default_pid_file))
  {
    app
      .add_option(
        "--cert",
        cert,
        "Use the provided certificate file when working with a SSL-based "
        "protocol.")
      ->required(false)
      ->check(CLI::ExistingFile);
    app
      .add_option(
        "--key",
        key,
        "Specify the path to the file containing the private key.")
      ->required(false)
      ->check(CLI::ExistingFile);
    app
      .add_option(
        "--cacert",
        rootCa,
        "Use the specified file for certificate verification.")
      ->required(false)
      ->check(CLI::ExistingFile);
    app
      .add_option(
        "--server-address",
        server_address,
        "Specify the address to submit requests.")
      ->capture_default_str();
    app
      .add_option(
        "--send-filepath",
        send_filepath,
        "Path to parquet file to store the submitted requests.")
      ->capture_default_str();
    app
      .add_option(
        "--response-filepath",
        response_filepath,
        "Path to parquet file to store the responses from the submitted "
        "requests.")
      ->capture_default_str();
    app
      .add_option(
        "--generator-filepath",
        generator_filepath,
        "Path to parquet file with the generated requests to be submitted.")
      ->capture_default_str();
    app.add_flag("--pipeline", pipeline, "Enable HTTP/1.1 pipelining option.")
      ->capture_default_str();
  }
};
