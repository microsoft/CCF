// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../ds/cli_helper.h"
#include "../ds/files.h"
#include "../node/rpc/jsonrpc.h"
#include "../tls/ca.h"
#include "../tls/cert.h"
#include "../tls/keypair.h"
#include "rpc_tls_client.h"

#include <CLI11/CLI11.hpp>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace std;
using namespace jsonrpc;

std::vector<uint8_t> make_rpc_raw(
  const string& host,
  const string& port,
  Pack pack,
  const string& ca_file,
  const string& req_arg,
  const string& client_cert_file = "",
  const string& client_pk_file = "",
  tls::Auth auth = tls::auth_required)
{
  auto ca = files::slurp(ca_file);
  auto req_str = req_arg;
  if (req_arg[0] == '@')
  {
    req_str = files::slurp_string(req_arg.substr(1));
  }

  std::vector<uint8_t> req(req_str.begin(), req_str.end());

  auto tls_ca = std::make_shared<tls::CA>(ca);
  auto cert = std::shared_ptr<tls::Cert>(nullptr);

  if (!client_cert_file.empty() && !client_pk_file.empty())
  {
    const auto client_cert = files::slurp(client_cert_file);
    const auto client_pk = files::slurp(client_pk_file);
    const tls::Pem pk_pem(client_pk);
    cert =
      std::make_shared<tls::Cert>(tls_ca, client_cert, pk_pem, nullb, auth);
  }

  const auto req_j = unpack(req, Pack::Text);

  switch (pack)
  {
    case Pack::MsgPack:
      req = nlohmann::json::to_msgpack(req_j);
      break;

    case Pack::Text:
      break;

    default:
      throw std::logic_error("Unexpected pack value");
      break;
  }

  vector<uint8_t> res;
  try
  {
    auto client = RpcTlsClient(host, port, tls_ca, cert);

#ifndef FTCP
    const auto method = req_j[jsonrpc::METHOD];
    auto r = enclave::http::Request(HTTP_POST);
    r.set_path(method);
    const auto request = r.build_request(req);
    res = client.call_raw(request);
#else
    // write framed data
    vector<uint8_t> len(4);
    auto p = len.data();
    auto size = len.size();
    serialized::write(p, size, (uint32_t)req.size());
    client.write(CBuffer(len));
    res = client.call_raw(req);
#endif
  }
  catch (const logic_error& err)
  {
    cout << err.what() << endl;
    return {};
  }

  return res;
}

nlohmann::json make_rpc(
  const string& host,
  const string& port,
  Pack pack,
  const string& ca_file,
  const string& client_cert_file,
  const string& client_pk_file,
  const string& req_arg,
  tls::Auth auth = tls::auth_required)
{
  auto s = make_rpc_raw(
    host, port, pack, ca_file, req_arg, client_cert_file, client_pk_file, auth);

  try
  {
    return unpack(s, pack);
  }
  catch (const exception& ex)
  {
    cerr << "Got response of unexpected format or error: "
         << string(s.begin(), s.end()) << ":" << ex.what() << endl;
    throw ex;
  }
  catch (...)
  {
    cerr << "Got response of unexpected format or error: "
         << string(s.begin(), s.end()) << endl;
    throw;
  }
  return nlohmann::json();
}

int main(int argc, char** argv)
{
  CLI::App app{"Generic RPC client"};

  bool pretty_print = false;
  app.add_flag(
    "--pretty-print",
    pretty_print,
    "Pretty print JSON responses with human-readable indentation");

  std::string host, port;
  std::string ca_file = "networkcert.pem";

  cli::ParsedAddress server_address;
  cli::add_address_option(
    app,
    server_address,
    "--rpc-address",
    "Remote node JSON-RPC server address");

  app.add_option("--ca", ca_file, "Network CA", true)
    ->required(true)
    ->check(CLI::ExistingFile);

  std::string req = "@rpc.json";
  std::string client_cert_file;
  std::string client_pk_file;
  app.add_option("--req", req, "RPC request data, '@' allowed", true);
  app
    .add_option(
      "--cert", client_cert_file, "Client certificate in PEM format", true)
    ->required(true)
    ->check(CLI::ExistingFile);
  app
    .add_option(
      "--pk", client_pk_file, "Client private key in PEM format", true)
    ->required(true)
    ->check(CLI::ExistingFile);

  CLI11_PARSE(app, argc, argv);

  try
  {
    nlohmann::json response;

    cout << fmt::format(
              "Sending RPC to {}:{}",
              server_address.hostname,
              server_address.port)
         << endl;

    response = make_rpc(
      server_address.hostname,
      server_address.port,
      Pack::MsgPack,
      ca_file,
      client_cert_file,
      client_pk_file,
      req);

    if (pretty_print)
    {
      std::cout << response.dump(2) << std::endl;
    }
    else
    {
      std::cout << response << std::endl;
    }
  }
  catch (const exception& ex)
  {
    cerr << "Unhandled exception: " << ex.what() << ". Aborting...\n";
    exit(-1);
  }
  catch (...)
  {
    cerr << "Unhandled non-std exception. Aborting...\n";
    exit(-1);
  }

  return 0;
}