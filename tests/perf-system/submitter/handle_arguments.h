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
  std::string server_address;
  std::string failover_server_address = "";
  std::string send_filepath;
  std::string response_filepath;
  std::string generator_filepath;
  int max_inflight_requests = 0;
  std::string pid_file_path = "submit.pid";

  ArgumentParser(const std::string& default_label, CLI::App& app) :
    label(default_label)
  {
    app
      .add_option(
        "-c,--cert",
        cert,
        "Use the provided certificate file when working with a SSL-based "
        "protocol.")
      ->required(true)
      ->check(CLI::ExistingFile);
    app
      .add_option(
        "-k,--key",
        key,
        "Specify the path to the file containing the private key.")
      ->required(true)
      ->check(CLI::ExistingFile);
    app
      .add_option(
        "--cacert",
        rootCa,
        "Use the specified file for certificate verification.")
      ->required(true)
      ->check(CLI::ExistingFile);
    app
      .add_option(
        "-a,--server-address",
        server_address,
        "Specify the address to submit requests.")
      ->required(true);
    app
      .add_option(
        "--failover-server-address",
        failover_server_address,
        "Specify failover address, in case connection to the main server address is lost.")
      ->capture_default_str();
    app
      .add_option(
        "-s,--send-filepath",
        send_filepath,
        "Path to parquet file to store the submitted requests.")
      ->required(true);
    app
      .add_option(
        "-r,--response-filepath",
        response_filepath,
        "Path to parquet file to store the responses from the submitted "
        "requests.")
      ->required(true);
    app
      .add_option(
        "-g,--generator-filepath",
        generator_filepath,
        "Path to parquet file with the generated requests to be submitted.")
      ->required(true);
    app
      .add_option(
        "-m,--max-writes-ahead",
        max_inflight_requests,
        "Specifies the number of outstanding requests sent to the server while "
        "waiting for response. When this options is set to 0 there will be no "
        "pipelining. Any other value will enable pipelining. A positive value "
        "will specify a window of outstanding requests on the server while "
        "waiting for a response. -1 or a negative value will set the window of "
        "outstanding requests to maximum i.e. submit requests without waiting "
        "for a response")
      ->capture_default_str();
    app
      .add_option(
        "--pid-file-path",
        pid_file_path,
        "Path to file where the pid of the submitter will be stored.")
      ->capture_default_str();
  }
};
