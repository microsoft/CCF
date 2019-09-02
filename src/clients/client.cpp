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

vector<uint8_t> slup_cert(const string& path)
{
  vector<uint8_t> cert;

  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  auto raw = files::slurp(path);
  if (mbedtls_x509_crt_parse(&crt, raw.data(), raw.size()))
  {
    cerr << "Failed to parse certificate " << path << endl;
    exit(-1);
  }
  cert = {crt.raw.p, crt.raw.p + crt.raw.len};
  return cert;
}

void dump(CBuffer b, const string& file)
{
  ofstream f(file, ios::binary | ios::trunc);
  f.write((char*)b.p, b.rawSize());

  if (!f)
  {
    cerr << "Failed to write to " << file << endl;
    exit(1);
  }
}

std::vector<uint8_t> make_rpc_raw(
  const string& host,
  const string& port,
  Pack pack,
  const string& sni,
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
    cert = std::make_shared<tls::Cert>(
      sni, tls_ca, client_cert, pk_pem, nullb, auth);
  }

  switch (pack)
  {
    case Pack::MsgPack:
      req = nlohmann::json::to_msgpack(unpack(req, Pack::Text));
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
    auto client = RpcTlsClient(host, port, sni, tls_ca, cert);

    // write framed data
    vector<uint8_t> len(4);
    auto p = len.data();
    auto size = len.size();
    serialized::write(p, size, (uint32_t)req.size());
    client.write(CBuffer(len));

    res = client.call_raw(req);
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
  const string& sni,
  const string& ca_file,
  const string& client_cert_file,
  const string& client_pk_file,
  const string& req_arg,
  tls::Auth auth = tls::auth_required)
{
  auto s = make_rpc_raw(
    host,
    port,
    pack,
    sni,
    ca_file,
    req_arg,
    client_cert_file,
    client_pk_file,
    auth);

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

CLI::Option* add_request_arg(CLI::App* app, std::string& req)
{
  return app->add_option("--req", req, "RPC request data, '@' allowed", true);
}

int main(int argc, char** argv)
{
  CLI::App app{"Generic RPC client"};

  app.require_subcommand(1, 1);

  bool pretty_print = false;
  app.add_flag(
    "--pretty-print",
    pretty_print,
    "Pretty print JSON responses with human-readable indentation");

  std::string host, port;
  std::string ca_file = "networkcert.pem";

  cli::ParsedAddress server_address;
  auto server_addr_opt = cli::add_address_option(
    app,
    server_address,
    "--rpc-address",
    "Remote node JSON-RPC server address");
  app.add_option("--ca", ca_file, "Network CA", true);

  auto member_rpc = app.add_subcommand("memberrpc", "Member RPC");

  std::string req_mem = "@memberrpc.json";
  std::string member_cert_file = "member1_cert.pem";
  std::string member_pk_file = "member1_privk.pem";
  add_request_arg(member_rpc, req_mem);
  member_rpc->add_option(
    "--cert", member_cert_file, "Member's certificate", true);
  member_rpc->add_option("--pk", member_pk_file, "Member's private key", true);

  auto user_rpc = app.add_subcommand("userrpc", "User RPC");

  std::string req_user = "@userrpc.json";
  std::string user_cert_file = "user1_cert.pem";
  std::string user_pk_file = "user1_privk.pem";
  add_request_arg(user_rpc, req_user);
  user_rpc->add_option("--cert", user_cert_file, "User's certificate", true);
  user_rpc->add_option("--pk", user_pk_file, "User's private key", true);

  auto mgmt_rpc = app.add_subcommand("mgmtrpc", "Management RPC");

  std::string req_mgmt = "@mgmt.json";
  std::string mgmt_cert_file;
  std::string mgmt_pk_file;
  add_request_arg(mgmt_rpc, req_mgmt);
  mgmt_rpc->add_option("--cert", mgmt_cert_file, "Manager's certificate", true);
  mgmt_rpc->add_option("--pk", mgmt_pk_file, "Manager's private key", true);

  CLI11_PARSE(app, argc, argv);

  try
  {
    host = server_address.hostname;
    port = server_address.port;

    nlohmann::json response;

    cout << fmt::format("Sending RPC to {}:{}", host, port) << endl;

    if (*member_rpc)
    {
      cout << "Doing member RPC:" << endl;
      response = make_rpc(
        host,
        port,
        Pack::MsgPack,
        "members",
        ca_file,
        member_cert_file,
        member_pk_file,
        req_mem);
    }

    if (*user_rpc)
    {
      cout << "Doing user RPC:" << endl;
      response = make_rpc(
        host,
        port,
        Pack::MsgPack,
        "users",
        ca_file,
        user_cert_file,
        user_pk_file,
        req_user);
    }

    if (*mgmt_rpc)
    {
      cout << "Doing management RPC:" << endl;
      response = make_rpc(
        host,
        port,
        Pack::MsgPack,
        "management",
        ca_file,
        mgmt_cert_file,
        mgmt_pk_file,
        req_mgmt);
    }

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