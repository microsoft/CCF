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

  void run()
  {
    constexpr auto record_id = 42;

    stringstream ss;
    timespec ts;
    timespec_get(&ts, TIME_UTC);
    ss << "[LEVEL] ";
    // ISO 8601, plus 6 digits of us, aka
    // YYYY-mm-ddTHH:MM:SS.uuuuuu
    ss << put_time(std::localtime(&ts.tv_sec), "%FT%T.") << setfill('0')
       << setw(6) << (ts.tv_nsec / 1000);
    ss << " Sample log message, for the purpose of testing";
    const auto record_msg = ss.str();

    // First transaction - record a log message
    {
      json params;
      params["id"] = record_id;
      params["msg"] = record_msg;

      const auto response_bytes = rpc_client->call("LOG_record", params);
      const json response = json::from_msgpack(response_bytes);

      const auto error_it = response.find("error");
      if (error_it != response.end())
      {
        throw std::runtime_error(
          "LOG_record returned error: " + error_it->dump());
      }

      cout << "Sent: " << params.dump() << endl;
      cout << "Received: " << response.dump() << endl;
    }

    // Second transaction - get a log message
    {
      json params;
      params["id"] = record_id;

      const auto response_bytes = rpc_client->call("LOG_get", params);
      const json response = json::from_msgpack(response_bytes);

      const auto error_it = response.find("error");
      if (error_it != response.end())
      {
        throw std::runtime_error("LOG_get returned error: " + error_it->dump());
      }

      cout << "Sent: " << params.dump() << endl;
      cout << "Received: " << response.dump() << endl;
    }
  }
};

int main(int argc, char** argv)
{
  string host;
  string port;
  uint64_t num_transactions;
  string cert_file, key_file, ca_file;

  {
    CLI::App cli_app{"Logging Client"};
    cli_app.add_option("--host", host);
    cli_app.add_option("--port", port);
    cli_app.add_option("--cert", cert_file)->required(true)->check(CLI::ExistingFile);
    cli_app.add_option("--privk", key_file)->required(true)->check(CLI::ExistingFile);
    cli_app.add_option("--ca", ca_file)->required(true)->check(CLI::ExistingFile);
    CLI11_PARSE(cli_app, argc, argv);
  }

  const auto raw_cert = files::slurp(cert_file);
  const auto raw_key = files::slurp(key_file);
  const auto ca = files::slurp(ca_file);

  const auto cert = make_shared<tls::Cert>(
    "users", make_shared<tls::CA>(ca), raw_cert, raw_key, nullb);

  LoggingClient client(host, port, cert);

  try
  {
    client.run();
  }
  catch (const char* e)
  {
    cout << "Error: " << e << endl;
    return 1;
  }
  catch (exception& e)
  {
    cout << "Exception: " << e.what() << endl;
    return 1;
  }

  return 0;
}
