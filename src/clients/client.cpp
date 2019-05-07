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

nlohmann::json make_rpc(
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
  auto s = make_rpc_raw(
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

  app.require_subcommand(1, 1);

  std::string nodes_file = "nodes.json";
  size_t node_index = 0;
  auto nodes_opt = app.add_option("--nodes", nodes_file, "Nodes file", true);
  app.add_option(
    "--host-node-index", node_index, "Index of host in nodes file", true);

  std::string host, port;
  std::string ca_file = "networkcert.pem";
  auto host_opt =
    app.add_option("--host", host, "Remote host")->excludes(nodes_opt);
  app.add_option("--port", port, "Remote port")->needs(host_opt);
  app.add_option("--ca", ca_file, "Network CA", true);

  auto start_network = app.add_subcommand("startnetwork", "Start network");

  std::string req_sn = "startNetwork.json";
  start_network->add_option("--req", req_sn, "RPC file", true);

  auto join_network = app.add_subcommand("joinnetwork", "Join network");

  std::string req_jn = "joinNetwork.json";
  join_network->add_option("--req", req_jn, "RPC file", true);

  auto member_rpc = app.add_subcommand("memberrpc", "Member RPC");

  std::string req_mem = "memberrpc.json";
  std::string member_cert_file = "member1_cert.pem";
  std::string member_pk_file = "member1_privk.pem";
  member_rpc->add_option("--req", req_mem, "RPC file", true);
  member_rpc->add_option(
    "--cert", member_cert_file, "Member's certificate", true);
  member_rpc->add_option("--pk", member_pk_file, "Member's private key", true);

  auto user_rpc = app.add_subcommand("userrpc", "User RPC");

  std::string req_user = "userrpc.json";
  std::string user_cert_file = "user1_cert.pem";
  std::string user_pk_file = "user1_privk.pem";
  user_rpc->add_option("--req", req_user, "RPC file", true);
  user_rpc->add_option("--cert", user_cert_file, "User's certificate", true);
  user_rpc->add_option("--pk", user_pk_file, "User's private key", true);

  auto mgmt_rpc = app.add_subcommand("mgmtrpc", "Management RPC");

  std::string req_mgmt = "mgmt.json";
  std::string mgmt_cert_file;
  std::string mgmt_pk_file;
  mgmt_rpc->add_option("--req", req_mgmt, "RPC file", true);
  mgmt_rpc->add_option("--cert", mgmt_cert_file, "Manager's certificate", true);
  mgmt_rpc->add_option("--pk", mgmt_pk_file, "Manager's private key", true);

  CLI11_PARSE(app, argc, argv);

  try
  {
    // If host connection has not been set explicitly by options then load from
    // nodes file
    if (!*host_opt)
    {
      const auto j_nodes = files::slurp_json(nodes_file);

      if (!j_nodes.is_array())
      {
        throw logic_error("Expected " + nodes_file + " to contain array");
      }

      if (node_index >= j_nodes.size())
      {
        throw logic_error(
          "Expected node data at index " + to_string(node_index) + ", but " +
          nodes_file + " defines only " + to_string(j_nodes.size()) + " files");
      }

      const auto& j_node = j_nodes[node_index];

      host = j_node["pubhost"];
      port = j_node["tlsport"];
    }

    if (*start_network)
    {
      cout << "Starting network:" << endl;
      Response<ccf::StartNetwork::Out> r = make_rpc(
        host, port, Pack::MsgPack, "management", ca_file, "", "", req_sn);

      dump(r.result.network_cert, "networkcert.pem");
      dump(r.result.tx0_sig, "tx0.sig");
    }

    if (*join_network)
    {
      cout
        << "Joining network:" << endl
        << make_rpc(
             host, port, Pack::MsgPack, "management", ca_file, "", "", req_jn)
        << endl;
    }

    if (*member_rpc)
    {
      cout << "Doing member RPC:" << endl
           << make_rpc(
                host,
                port,
                Pack::MsgPack,
                "members",
                ca_file,
                member_cert_file,
                member_pk_file,
                req_mem)
           << endl;
    }

    if (*user_rpc)
    {
      cout << "Doing user RPC:" << endl
           << make_rpc(
                host,
                port,
                Pack::MsgPack,
                "users",
                ca_file,
                user_cert_file,
                user_pk_file,
                req_user)
           << endl;
    }

    if (*mgmt_rpc)
    {
      cout << "Doing management RPC:" << endl
           << make_rpc(
                host,
                port,
                Pack::MsgPack,
                "management",
                ca_file,
                mgmt_cert_file,
                mgmt_pk_file,
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