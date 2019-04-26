// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../ds/files.h"
#include "../node/calltypes.h"
#include "../node/rpc/jsonrpc.h"
#include "../node/rpc/serialization.h"
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

vector<uint8_t> slurpCert(const string& path)
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

std::vector<uint8_t> makeRpcRaw(
  const string& host,
  const string& port,
  Pack pack,
  const string& sni,
  const string& ca_file,
  const string& req_file,
  const string& client_cert_file = "",
  const string& client_pk_file = "",
  tls::Auth auth = tls::auth_required)
{
  auto ca = files::slurp(ca_file);
  auto req = files::slurp(req_file);

  auto tls_ca = std::make_shared<tls::CA>(ca);

  auto cert = std::shared_ptr<tls::Cert>(nullptr);

  if (!client_cert_file.empty() && !client_pk_file.empty())
  {
    auto client_cert = files::slurp(client_cert_file);
    auto client_pk = files::slurp(client_pk_file);
    cert = std::make_shared<tls::Cert>(
      sni, tls_ca, client_cert, client_pk, nullb, auth);
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

nlohmann::json makeRpc(
  const string& host,
  const string& port,
  Pack pack,
  const string& sni,
  const string& ca_file,
  const string& client_cert_file,
  const string& client_pk_file,
  const string& req_file,
  tls::Auth auth = tls::auth_required)
{
  auto s = makeRpcRaw(
    host,
    port,
    pack,
    sni,
    ca_file,
    req_file,
    client_cert_file,
    client_pk_file,
    auth);

  try
  {
    return unpack(s, pack);
  }
  catch (const exception& ex)
  {
    cerr << "Got response of unexpected format or error: " << string(s.begin(), s.end()) << ":"
         << ex.what() << endl;
    throw ex;
  }
  catch (...)
  {
    cerr << "Got response of unexpected format or error: " << string(s.begin(), s.end()) << endl;
    throw;
  }
  return nlohmann::json();
}

int main(int argc, char** argv)
{
  CLI::App app{"Generic RPC client"};

  app.require_subcommand(1, 1);

  std::string host, port, ca_file;

  app.add_option("--host", host, "Remote host")->required(true);
  app.add_option("--port", port, "Remote port")->required(true);
  app.add_option("--ca", ca_file, "CA")->required(true);

  auto start_network = app.add_subcommand("startnetwork", "Start network");

  std::string req_sn = "startNetwork.json";
  start_network->add_option("--req", req_sn, "RPC file", true);

  auto join_network = app.add_subcommand("joinnetwork", "Join network");

  join_network->add_option(
    "--server-cert", ca_file, "Server certificate", true);

  std::string req_jn = "joinNetwork.json";
  join_network->add_option("--req", req_jn, "RPC file", true);

  std::string cert_file = "";
  std::string pk_file = "";

  auto member_rpc = app.add_subcommand("memberrpc", "Member RPC");

  std::string req_mem = "memberrpc.json";
  member_rpc->add_option("--req", req_mem, "RPC file", true);
  member_rpc->add_option("--cert", cert_file, "Client certificate", true);
  member_rpc->add_option("--pk", pk_file, "Private key", true);

  auto user_rpc = app.add_subcommand("userrpc", "User RPC");

  std::string req_user = "userrpc.json";
  user_rpc->add_option("--req", req_user, "RPC file", true);
  user_rpc->add_option("--cert", cert_file, "Client certificate", true);
  user_rpc->add_option("--pk", pk_file, "Private key", true);

  auto mgmt_rpc = app.add_subcommand("mgmtrpc", "Management RPC");

  std::string req_mgmt = "mgmt.json";
  mgmt_rpc->add_option("--req", req_mgmt, "RPC file", true);
  mgmt_rpc->add_option("--cert", cert_file, "Client certificate", true);
  mgmt_rpc->add_option("--pk", pk_file, "Private key", true);

  CLI11_PARSE(app, argc, argv);

  try
  {
    if (*start_network)
    {
      cout << "Starting network:" << endl;
      Response<ccf::StartNetwork::Out> r = makeRpc(
        host, port, Pack::MsgPack, "management", ca_file, "", "", req_sn);

      dump(r.result.network_cert, "networkcert.pem");
      dump(r.result.tx0_sig, "tx0.sig");
    }
    if (*join_network)
    {
      cout << "Joining network:" << endl
           << makeRpc(
                host, port, Pack::MsgPack, "management", ca_file, "", "", req_jn)
           << endl;
    }
    if (*member_rpc)
    {
      cout << "Doing member RPC:" << endl
           << makeRpc(
                host,
                port,
                Pack::MsgPack,
                "members",
                ca_file,
                cert_file,
                pk_file,
                req_mem)
           << endl;
    }
    if (*user_rpc)
    {
      cout << "Doing user RPC:" << endl
           << makeRpc(
                host,
                port,
                Pack::MsgPack,
                "users",
                ca_file,
                cert_file,
                pk_file,
                req_user)
           << endl;
    }
    if (*mgmt_rpc)
    {
      cout << "Doing management RPC:" << endl
           << makeRpc(
                host,
                port,
                Pack::MsgPack,
                "management",
                ca_file,
                cert_file,
                pk_file,
                req_mgmt)
           << endl;
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