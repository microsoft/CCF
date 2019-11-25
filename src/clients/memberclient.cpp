// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "crypto/hash.h"
#include "ds/cli_helper.h"
#include "ds/files.h"
#include "node/entities.h"
#include "node/members.h"
#include "node/nodes.h"
#include "node/proposals.h"
#include "node/rpc/jsonrpc.h"
#include "node/script.h"
#include "rpc_tls_client.h"
#include "sig_rpc_tls_client.h"
#include "tls/keypair.h"

#include <CLI11/CLI11.hpp>
#include <limits>

using namespace ccf;
using namespace files;
using namespace jsonrpc;
using namespace std;
using namespace nlohmann;

static const string add_member_proposal(R"xxx(
      tables, member_cert = ...
      return Calls:call("new_member", member_cert)
    )xxx");

static const string add_user_proposal(R"xxx(
      tables, user_cert = ...
      return Calls:call("new_user", user_cert)
    )xxx");

static const string accept_node_proposal(R"xxx(
      tables, node_id = ...
      return Calls:call("trust_node", node_id)
    )xxx");

static const string retire_node_proposal(R"xxx(
      tables, node_id = ...
      return Calls:call("retire_node", node_id)
    )xxx");

static const string vote_ballot_accept(R"xxx(
      tables, changes = ...
      return true)xxx");

static const string vote_ballot_reject(R"xxx(
      tables, changes = ...
      return false)xxx");

static const string read_proposals = R"xxx(
      tables = ...
      local proposals = {}
      tables["ccf.proposals"]:foreach( function(k, v)
         proposals[tostring(k)] = v;
      end )
      return proposals;
    )xxx";

static const string accept_recovery_proposal(R"xxx(
      tables, sealed_secrets = ...
      return Calls:call("accept_recovery", sealed_secrets)
    )xxx");

static const string open_network_proposal(R"xxx(
      tables = ...
      return Calls:call("open_network")
    )xxx");

static const string accept_code_proposal(R"xxx(
      tables, code_digest = ...
      return Calls:call("new_code", code_digest)
    )xxx");

static const string set_lua_app(R"xxx(
      tables, app = ...
      return Calls:call("set_lua_app", app)
    )xxx");

json proposal_params(const string& script)
{
  return Propose::In{script};
}

template <typename T>
json proposal_params(const string& script, const T& parameter)
{
  return Propose::In{script, parameter};
}

auto query_params(const string& script)
{
  json params;
  params["text"] = script;
  return params;
}

auto ack_params(const vector<uint8_t>& sig)
{
  json params;
  params["sig"] = sig;
  return params;
}

template <typename T>
auto read_params(const T& key, const string& table_name)
{
  json params;
  params["key"] = key;
  params["table"] = table_name;
  return params;
}

template <size_t SZ>
void hex_str_to_bytes(const std::string& src, std::array<uint8_t, SZ>& dst)
{
  if (src.length() != SZ * 2)
  {
    throw logic_error("Invalid code id length");
  }

  for (size_t i = 0; i < SZ; ++i)
  {
    auto cur_byte_str = src.substr(i * 2, 2);
    dst[i] = static_cast<uint8_t>(strtoul(cur_byte_str.c_str(), nullptr, 16));
  }
}

void add_new(
  RpcTlsClient& tls_connection, const string& cert_file, const string& proposal)
{
  const auto cert = slurp(cert_file);
  const auto params = proposal_params(proposal, cert);
  const auto response =
    json::from_msgpack(tls_connection.call("propose", params));
  cout << response.dump() << endl;
}

void submit_accept_node(RpcTlsClient& tls_connection, NodeId node_id)
{
  auto params = proposal_params<NodeId>(accept_node_proposal, node_id);
  const auto response =
    json::from_msgpack(tls_connection.call("propose", params));
  cout << response.dump() << endl;
}

void submit_accept_code(RpcTlsClient& tls_connection, std::string& new_code_id)
{
  CodeDigest digest;
  // we expect a string representation of the code id,
  // so every byte is represented by 2 characters
  // before conversion
  hex_str_to_bytes<ccf::CODE_DIGEST_BYTES>(new_code_id, digest);

  auto params = proposal_params<CodeDigest>(accept_code_proposal, digest);
  const auto response =
    json::from_msgpack(tls_connection.call("propose", params));
  cout << response.dump() << endl;
}

void submit_retire_node(RpcTlsClient& tls_connection, NodeId node_id)
{
  auto params = proposal_params<NodeId>(retire_node_proposal, node_id);
  const auto response =
    json::from_msgpack(tls_connection.call("propose", params));
  cout << response.dump() << endl;
}

void submit_accept_recovery(
  RpcTlsClient& tls_connection, const string& sealed_secrets_file)
{
  const auto sealed_secrets = slurp_json(sealed_secrets_file);
  const auto params =
    proposal_params<json>(accept_recovery_proposal, sealed_secrets);
  const auto response =
    json::from_msgpack(tls_connection.call("propose", params));
  cout << response.dump() << std::endl;
}

void submit_open_network(RpcTlsClient& tls_connection)
{
  const auto params = proposal_params(open_network_proposal);
  const auto response =
    json::from_msgpack(tls_connection.call("propose", params));
  cout << response.dump() << std::endl;
}

void submit_set_lua_app(RpcTlsClient& tls_connection, const std::string& app)
{
  const auto params = proposal_params<json>(set_lua_app, app);
  const auto response =
    json::from_msgpack(tls_connection.call("propose", params));
  cout << response.dump() << std::endl;
}

void submit_raw_puts(
  RpcTlsClient& tls_connection, const string& script, const string& param_file)
{
  auto v = files::slurp(param_file, true);
  json param;
  if (v.size() == 0)
  {
    param["p"] = json::object();
  }
  else
  {
    param = json::parse(v.begin(), v.end());
  }
  const auto response = json::from_msgpack(
    tls_connection.call("propose", proposal_params(script, param["p"])));
  cout << response << endl;
}

void submit_withdraw(RpcTlsClient& tls_connection, ObjectId proposal_id)
{
  const auto response = json::from_msgpack(
    tls_connection.call("withdraw", ProposalAction{proposal_id}));
  cout << response << endl;
}

void submit_vote(
  RpcTlsClient& tls_connection, ObjectId proposal_id, const string& vote_script)
{
  const auto response = json::from_msgpack(
    tls_connection.call("vote", Vote{proposal_id, vote_script}));
  cout << response.dump() << endl;
}

void submit_query(RpcTlsClient& tls_connection, const string& query_script)
{
  const auto response = json::from_msgpack(
    tls_connection.call("query", query_params(query_script)));
  cout << response.dump() << endl;
}

void display_proposals(RpcTlsClient& tls_connection)
{
  auto params = query_params(read_proposals);
  Response<json> response =
    json::from_msgpack(tls_connection.call("query", params));
  cout << endl;
  cout << response.result;
}

void submit_ack(
  RpcTlsClient& tls_connection,
  const vector<uint8_t>& raw_cert,
  const tls::Pem& key)
{
  // member using its own certificate reads its member id
  auto verifier = tls::make_verifier(raw_cert);
  Response<ObjectId> read_id = json::from_msgpack(tls_connection.call(
    "read", read_params(verifier->der_cert_data(), Tables::MEMBER_CERTS)));
  const auto member_id = read_id.result;

  // member reads nonce
  Response<MemberAck> read_ack = json::from_msgpack(
    tls_connection.call("read", read_params(member_id, Tables::MEMBER_ACKS)));

  // member signs nonce and sends ack
  auto kp = tls::make_key_pair(key);
  const auto sig = kp->sign(read_ack.result.next_nonce);
  const auto response =
    json::from_msgpack(tls_connection.call("ack", ack_params(sig)));
  cout << response << endl;
}

int main(int argc, char** argv)
{
  CLI::App app{"Member client"};
  app.fallthrough(true);
  app.allow_extras(true);

  cli::ParsedAddress server_address;
  cli::add_address_option(
    app, server_address, "--rpc-address", "Remote node RPC over TLS address")
    ->required();

  string cert_file, privk_file, ca_file;
  app.add_option("--cert", cert_file, "Client certificate in PEM format")
    ->required(true)
    ->check(CLI::ExistingFile);
  app.add_option("--privk", privk_file, "Client private key in PEM format")
    ->required(true)
    ->check(CLI::ExistingFile);
  app.add_option("--ca", ca_file, "CA")
    ->required(true)
    ->check(CLI::ExistingFile);

  bool force_unsigned = false;
  app.add_flag(
    "--force-unsigned", force_unsigned, "Force sending the request unsigned");

  auto add_member = app.add_subcommand("add_member", "Add a new member");
  string member_cert_file;
  add_member
    ->add_option("--member-cert", member_cert_file, "New member certificate")
    ->required(true)
    ->check(CLI::ExistingFile);

  auto add_user = app.add_subcommand("add_user", "Add a new user");
  string user_cert_file;
  add_user->add_option("--user-cert", user_cert_file, "New user certificate")
    ->required(true)
    ->check(CLI::ExistingFile);

  auto proposal_display =
    app.add_subcommand("proposal_display", "Display all proposals");

  ObjectId proposal_id;
  string vote_file;
  bool accept;
  bool reject;

  auto vote = app.add_subcommand("vote", "Accept a proposal");
  vote->add_option("--script", vote_file, "Vote lua script")
    ->check(CLI::ExistingFile);
  vote->add_option("--proposal-id", proposal_id, "The proposal id")
    ->required(true);
  vote->add_flag("--accept", accept, "Accept the proposal");
  vote->add_flag("--reject", reject, "Reject the proposal");

  string query_file;
  auto query = app.add_subcommand("query", "Submit a query");
  query->add_option("--script", query_file, "Query lua script")
    ->required(true)
    ->check(CLI::ExistingFile);

  auto ack =
    app.add_subcommand("ack", "Acknowledge self added into the network");

  std::string new_code_id;
  auto add_code = app.add_subcommand("add_code", "Support executing new code");
  add_code
    ->add_option(
      "--new-code-id",
      new_code_id,
      "The new code id (a 64 character string representing a 32 byte hash "
      "value in hex format)")
    ->required(true);

  NodeId node_id;
  auto trust_node = app.add_subcommand("trust_node", "Make a node trusted");
  trust_node->add_option("--node-id", node_id, "The node id")->required(true);

  auto retire_node = app.add_subcommand("retire_node", "Make a node retired");
  retire_node->add_option("--node-id", node_id, "The node id")->required(true);

  string param_file;
  string script_file;
  auto raw_puts = app.add_subcommand("raw_puts", "Propose kv modifications");
  raw_puts
    ->add_option(
      "--param",
      param_file,
      "Parameter file passed into raw_puts in json format")
    ->check(CLI::ExistingFile);
  raw_puts->add_option("--script", script_file, "Raw puts lua script")
    ->required(true)
    ->check(CLI::ExistingFile);

  auto withdraw = app.add_subcommand("withdraw", "Withdraw a proposal");
  withdraw->add_option("--proposal-id", proposal_id, "The proposal id")
    ->required(true);

  auto open_network = app.add_subcommand(
    "open_network",
    "Open the network for users to issue business transactions");

  auto accept_recovery =
    app.add_subcommand("accept_recovery", "Accept to recover network");

  auto set_lua_app =
    app.add_subcommand("set_lua_app", "Update lua application");
  string lua_app_file;
  set_lua_app
    ->add_option("--lua-app-file", lua_app_file, "Lua application file")
    ->required(true)
    ->check(CLI::ExistingFile);

  string sealed_secrets_file;
  accept_recovery
    ->add_option(
      "--sealed-secrets",
      sealed_secrets_file,
      "Sealed secrets required to recover the network")
    ->required(true)
    ->check(CLI::ExistingFile);

  CLI11_PARSE(app, argc, argv);

  const auto raw_cert = slurp(cert_file);
  const auto raw_key = slurp(privk_file);
  const auto ca = files::slurp(ca_file);

  const tls::Pem key_pem(raw_key);

  // create tls client
  auto tls_cert =
    make_shared<tls::Cert>(make_shared<tls::CA>(ca), raw_cert, key_pem);

  unique_ptr<RpcTlsClient> tls_connection = force_unsigned ?
    make_unique<RpcTlsClient>(
      server_address.hostname, server_address.port, nullptr, tls_cert) :
    make_unique<SigRpcTlsClient>(
      key_pem, server_address.hostname, server_address.port, nullptr, tls_cert);
  tls_connection->set_prefix("members");

  try
  {
    if (*add_member)
    {
      add_new(*tls_connection, member_cert_file, add_member_proposal);
    }

    if (*add_user)
    {
      add_new(*tls_connection, user_cert_file, add_user_proposal);
    }

    if (*add_code)
    {
      submit_accept_code(*tls_connection, new_code_id);
    }

    if (*trust_node)
    {
      submit_accept_node(*tls_connection, node_id);
    }

    if (*retire_node)
    {
      submit_retire_node(*tls_connection, node_id);
    }

    if (*raw_puts)
    {
      const auto script = slurp_string(script_file);
      submit_raw_puts(*tls_connection, script, param_file);
    }

    if (*withdraw)
    {
      submit_withdraw(*tls_connection, proposal_id);
    }

    if (*proposal_display)
    {
      display_proposals(*tls_connection);
    }

    if (*vote)
    {
      if (!vote_file.empty())
      {
        const auto vote_script = slurp_string(vote_file);
        submit_vote(*tls_connection, proposal_id, vote_script);
      }
      else
      {
        if (accept && reject)
        {
          throw logic_error(
            "You can either accept or reject a proposal, not both.");
        }
        if (accept)
        {
          submit_vote(*tls_connection, proposal_id, vote_ballot_accept);
        }
        if (reject)
        {
          submit_vote(*tls_connection, proposal_id, vote_ballot_reject);
        }
      }
    }

    if (*query)
    {
      const auto query_script = slurp_string(query_file);
      submit_query(*tls_connection, query_script);
    }

    if (*ack)
    {
      submit_ack(*tls_connection, raw_cert, key_pem);
    }

    if (*accept_recovery)
    {
      submit_accept_recovery(*tls_connection, sealed_secrets_file);
    }

    if (*open_network)
    {
      submit_open_network(*tls_connection);
    }

    if (*set_lua_app)
    {
      submit_set_lua_app(*tls_connection, slurp_string(lua_app_file));
    }
  }
  catch (const exception& ex)
  {
    cerr << "Unhandled exception: " << ex.what() << ". Aborting..." << endl;
    exit(-1);
  }
  catch (...)
  {
    cerr << "Unhandled non-std exception. Aborting..." << endl;
    exit(-1);
  }
  return 0;
}
