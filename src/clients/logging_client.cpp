// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/files.h"
#include "rpc_tls_client.h"

#include <CLI11/CLI11.hpp>
#include <ctime>
#include <iomanip>
#include <nlohmann/json.hpp>

using namespace std;
using namespace nlohmann;

class LoggingClient
{
  unique_ptr<RpcTlsClient> rpc_client;

public:
  LoggingClient(
    const string& host, const string& port, const shared_ptr<tls::Cert>& cert) :
    rpc_client(make_unique<RpcTlsClient>(host, port, "users", nullptr, cert))
  {}

  static std::string make_timestamped_message(const std::string& body)
  {
    stringstream ss;
    timespec ts;
    timespec_get(&ts, TIME_UTC);
    ss << "[LEVEL] ";
    // ISO 8601, plus 6 digits of us, aka
    // YYYY-mm-ddTHH:MM:SS.uuuuuu
    ss << put_time(std::localtime(&ts.tv_sec), "%FT%T.") << setfill('0')
       << setw(6) << (ts.tv_nsec / 1000);
    ss << " " << body;
    return ss.str();
  }

  void record_log_message(
    size_t id, const std::string& msg, bool print_status = true)
  {
    json params;
    params["id"] = id;
    params["msg"] = msg;

    const auto response_bytes = rpc_client->call("LOG_record", params);
    const json response = json::from_msgpack(response_bytes);

    const auto error_it = response.find("error");
    if (error_it != response.end())
    {
      throw std::runtime_error(
        "LOG_record returned error: " + error_it->dump());
    }

    if (print_status)
    {
      cout << "Sent: " << params.dump() << endl;
      cout << "Received: " << response.dump() << endl;
    }
  }

  void get_log_message(size_t id, bool print_status = true)
  {
    json params;
    params["id"] = id;

    const auto response_bytes = rpc_client->call("LOG_get", params);
    const json response = json::from_msgpack(response_bytes);

    const auto error_it = response.find("error");
    if (error_it != response.end())
    {
      throw std::runtime_error("LOG_get returned error: " + error_it->dump());
    }

    if (print_status)
    {
      cout << "Sent: " << params.dump() << endl;
      cout << "Received: " << response.dump() << endl;
    }
  }
};

int main(int argc, char** argv)
{
  string host;
  string port;
  size_t num_messages = 1;
  size_t msg_id = 42;
  std::string msg_body = "Sample log message, for the purposes of testing";
  string cert_file, key_file, ca_file;

  CLI::App* multi_command = nullptr;

  {
    CLI::App cli_app{"Logging Client"};
    cli_app.require_subcommand(0, 1);

    cli_app.add_option("--host", host);
    cli_app.add_option("--port", port);
    cli_app.add_option("--cert", cert_file)
      ->required(true)
      ->check(CLI::ExistingFile);
    cli_app.add_option("--privk", key_file)
      ->required(true)
      ->check(CLI::ExistingFile);
    cli_app.add_option("--ca", ca_file)
      ->required(true)
      ->check(CLI::ExistingFile);

    multi_command =
      cli_app.add_subcommand("multiple", "Send multiple log messages");

    multi_command->add_option(
      "--msg-count", num_messages, "Number of log messages to record", true);
    multi_command->add_option(
      "--msg-id", msg_id, "ID to be used for first log message", true);
    multi_command->add_option(
      "--msg-body", msg_body, "Body of log sent with each message");

    CLI11_PARSE(cli_app, argc, argv);
  }

  const auto raw_cert = files::slurp(cert_file);
  const auto raw_key = files::slurp(key_file);
  const auto ca = files::slurp(ca_file);

  const auto cert = make_shared<tls::Cert>(
    "users", make_shared<tls::CA>(ca), raw_cert, raw_key, nullb);

  LoggingClient client(host, port, cert);

  if (*multi_command)
  {
    const size_t final_msg_id = msg_id + num_messages - 1;
    for (auto id = msg_id; id <= final_msg_id; ++id)
    {
      // Only print response and retrieve log for first and last messages
      bool const print_status = id == msg_id || id == final_msg_id;

      const auto record_msg = client.make_timestamped_message(msg_body);

      client.record_log_message(id, record_msg, print_status);

      if (print_status)
      {
        client.get_log_message(id);
      }
    }
  }
  else
  {
    const auto record_msg = client.make_timestamped_message(msg_body);

    // First transaction - record a log message
    client.record_log_message(msg_id, record_msg);

    // Second transaction - get a log message
    client.get_log_message(msg_id);
  }

  return 0;
}
