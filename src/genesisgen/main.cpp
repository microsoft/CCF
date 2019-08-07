// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/files.h"
#include "genesisgen.h"
#include "luainterp/luainterp.h"
#include "runtime_config/default_whitelists.h"
#include "tls/cert.h"
#include "tls/keypair.h"

#include <CLI11/CLI11.hpp>
#include <fstream>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <glob.h>
#endif

using namespace std;
using namespace tls;
using namespace ccf;

tls::Cert gen_cert(const string& name)
{
  auto k = tls::make_key_pair();
  auto cert = k->self_sign("CN=" + name);
  auto privk = k->private_key_pem();

  ofstream(name + "_cert.pem", ios_base::trunc | ios::binary)
    .write((char*)cert.data(), cert.size());
  ofstream(name + "_privk.pem", ios_base::trunc | ios::binary)
    .write((char*)privk.data(), privk.size());

  return {name, nullptr, cert, privk, nullb, tls::auth_required};
}

vector<vector<uint8_t>> slurp_certs(const string& path, bool optional = false)
{
  vector<vector<uint8_t>> certs;

#ifdef _WIN32
  WIN32_FIND_DATA fd;
  auto h = FindFirstFile(path.c_str(), &fd);

  if (h == INVALID_HANDLE_VALUE)
  {
    if (optional)
    {
      return {};
    }
    else
    {
      cerr << "Failed to search for cert pattern." << endl;
      exit(-1);
    }
  }
#else
  glob_t g;
  size_t i = 0;

  if (glob(path.c_str(), GLOB_ERR, NULL, &g) || g.gl_pathc < 1)
  {
    if (optional)
    {
      return {};
    }
    else
    {
      cerr << "Failed to search for cert pattern." << endl;
      exit(-1);
    }
  }
#endif

  do
  {
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    string fn;
#ifdef _WIN32
    fn = fd.cFileName;
#else
    fn = g.gl_pathv[i];
#endif

    auto raw = files::slurp(fn);

    if (mbedtls_x509_crt_parse(&cert, raw.data(), raw.size()))
    {
      cerr << "Failed to parse certificate " << fn << endl;
      exit(-1);
    }

    certs.push_back({cert.raw.p, cert.raw.p + cert.raw.len});
    mbedtls_x509_crt_free(&cert);
  } while (
#ifdef _WIN32
    FindNextFile(h, &fd)
#else
    ++i < g.gl_pathc
#endif
  );

#ifdef _WIN32
  FindClose(h);
#else
  globfree(&g);
#endif

  return certs;
}

int main(int argc, char** argv)
{
  CLI::App app{"Genesis Transaction Generator"};
  app.require_subcommand(1, 1);

  // Users/Members certificate generation
  auto cert = app.add_subcommand("cert", "Generate certificate");
  string name = "member3";
  cert->add_option("--name", name, "Member name", true);

  // Genesis transaction generation
  auto tx_cmd = app.add_subcommand("tx", "Create genesis transaction");

  bool accepted;
  tx_cmd->add_flag("--accepted", accepted);

  string member_certs_file = "member*cert.pem";
  tx_cmd->add_option(
    "--members",
    member_certs_file,
    "Globbing pattern for member cert files",
    true);

  string user_certs_file = "user*cert.pem";
  tx_cmd->add_option(
    "--users", user_certs_file, "Globbing pattern for user cert files", true);

  string nodes_json_file = "nodes.json";
  tx_cmd
    ->add_option("--nodes", nodes_json_file, "Nodes table as a JSON file", true)
    ->check(CLI::ExistingFile);

  string tx0_file = "tx0";
  tx_cmd->add_option(
    "--tx0",
    tx0_file,
    "Path to which the serialised genesis transaction will be written",
    true);

  string start_json = "startNetwork.json";
  tx_cmd->add_option(
    "--start-json", start_json, "Start network RPC as a JSON file", true);

  string gov_script = "gov.lua";
  tx_cmd
    ->add_option(
      "--gov-script",
      gov_script,
      "Path to Lua file that defines the contents of the gov_scripts table",
      true)
    ->check(CLI::ExistingFile);

  string app_script;
  const auto app_script_opt = tx_cmd->add_option(
    "--app-script",
    app_script,
    "Path to Lua file that defines the contents of the app_scripts table",
    false);

  // Join network RPC generation
  auto join_rpc = app.add_subcommand("joinrpc", "Create join RPC");
  string network_cert_file = "networkcert.pem";

  join_rpc->add_option(
    "--network-cert",
    network_cert_file,
    "Network certificate required for joining nodes to verify identity of "
    "network",
    true);

  string join_host;
  join_rpc->add_option("--host", join_host, "Target host")->required();

  string join_port;
  join_rpc->add_option("--port", join_port, "Target port")->required();

  string join_json = "joinNetwork.json";
  join_rpc->add_option(
    "--join-json", join_json, "Join network RPC as a JSON file", true);

  CLI11_PARSE(app, argc, argv);

  if (*cert)
  {
    gen_cert(name);
    return 0;
  }
  else if (*tx_cmd)
  {
    auto user_certs = slurp_certs(user_certs_file);
    auto member_certs = slurp_certs(member_certs_file);
    vector<NodeInfo> nodes = files::slurp_json(nodes_json_file);

    auto member_status =
      accepted ? MemberStatus::ACCEPTED : MemberStatus::ACTIVE;

    GenesisGenerator g;
    for (auto& cert : member_certs)
      g.add_member(cert, member_status);

    for (auto& cert : user_certs)
      g.add_user(cert);

    for (auto& node : nodes)
      g.add_node(node);

    // set access whitelists
    // TODO(#feature): this should be parsed from a config file
    for (const auto& wl : default_whitelists)
      g.set_whitelist(wl.first, wl.second);

    g.set_gov_scripts(lua::Interpreter().invoke<nlohmann::json>(
      files::slurp_string(gov_script)));

    if (*app_script_opt)
      g.set_app_scripts(lua::Interpreter().invoke<nlohmann::json>(
        files::slurp_string(app_script)));

    g.finalize(tx0_file, start_json);
  }
  else if (*join_rpc)
  {
    // Network certificate is required for joining nodes to verify the identity
    // of the network. Also read the genesis transaction to find out about all
    // nodes in the network.
    auto network_cert = files::slurp(network_cert_file);
    GenesisGenerator g;

    // For now, the node to contact to join the network is the first one
    g.create_join_rpc(join_host, join_port, join_json, network_cert);
  }

  cout << "Done." << endl;
  return 0;
}
