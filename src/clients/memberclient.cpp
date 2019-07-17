// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "crypto/hash.h"
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

constexpr auto members_sni = "members";
constexpr NodeId INVALID_NODE_ID = std::numeric_limits<NodeId>::max();

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
      return Calls:call("accept_node", node_id)
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
      tables["proposals"]:foreach( function(k, v)
         proposals[tostring(k)] = v;
      end )
      return proposals;
    )xxx";

static const string accept_recovery_proposal(R"xxx(
      tables, sealed_secrets = ...
      return Calls:call("accept_recovery", sealed_secrets)
    )xxx");

static const string accept_code_proposal(R"xxx(
      tables, code_digest = ...
      return Calls:call("new_code", code_digest)
    )xxx");

template <typename T>
json proposal_params(const string& script, const T& parameter)
{
  return Proposal::In{script, parameter};
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
  auto verifier = tls::make_verifier(cert);
  const auto params = proposal_params(proposal, verifier->raw_cert_data());
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

NodeId submit_add_node(RpcTlsClient& tls_connection, NodeInfo& node_info)
{
  const auto response =
    json::from_msgpack(tls_connection.call("add_node", node_info));

  cout << response.dump() << endl;

  auto result = response.find("result");
  if (result == response.end())
    return INVALID_NODE_ID;

  auto ret_id = result->find("id");
  if (ret_id == result->end())
    return INVALID_NODE_ID;

  return *ret_id;
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

void submit_removal(RpcTlsClient& tls_connection, ObjectId proposal_id)
{
  const auto response = json::from_msgpack(
    tls_connection.call("removal", ProposalAction{proposal_id}));
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
  const vector<uint8_t>& raw_key)
{
  // member using its own certificate reads its member id
  auto verifier = tls::make_verifier(raw_cert);
  Response<ObjectId> read_id = json::from_msgpack(tls_connection.call(
    "read", read_params(verifier->raw_cert_data(), "membercerts")));
  const auto member_id = read_id.result;

  // member reads nonce
  Response<MemberAck> read_ack = json::from_msgpack(
    tls_connection.call("read", read_params(member_id, "memberacks")));

  // member signs nonce and sends ack
  auto kp = tls::make_key_pair(raw_key);
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
  string host = "localhost";
  app.add_option("--host", host, "Remote host")->required(true);
  string port = "5678";
  app.add_option("--port", port, "Remote port")->required(true);

  string cert_file, privk_file, ca_file;
  app.add_option("--cert", cert_file, "Client certificate")
    ->required(true)
    ->check(CLI::ExistingFile);
  app.add_option("--privk", privk_file, "Client private key")
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
    ->add_option("--member_cert", member_cert_file, "New member certificate")
    ->required(true)
    ->check(CLI::ExistingFile);

  auto add_user = app.add_subcommand("add_user", "Add a new user");
  string user_cert_file;
  add_user->add_option("--user_cert", user_cert_file, "New user certificate")
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

  std::string nodes_file;
  auto add_node = app.add_subcommand("add_node", "Add a node");
  add_node
    ->add_option(
      "--nodes_to_add", nodes_file, "The file containing the nodes to be added")
    ->required(true);

  std::string new_code_id;
  auto add_code = app.add_subcommand("add_code", "Support executing new code");
  add_code
    ->add_option(
      "--new_code_id",
      new_code_id,
      "The new code id (a 64 character string representing a 32 byte hash "
      "value in hex format)")
    ->required(true);

  NodeId node_id;
  auto accept_node = app.add_subcommand("accept_node", "Make a node trusted");
  accept_node->add_option("--node-id", node_id, "The node id")->required(true);

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

  auto removal = app.add_subcommand("removal", "Remove a proposal");
  removal->add_option("--id", proposal_id, "The proposal id")->required(true);

  auto accept_recovery =
    app.add_subcommand("accept_recovery", "Accept to recover network");

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

  // create tls client
  auto tls_cert = make_shared<tls::Cert>(
    members_sni, make_shared<tls::CA>(ca), raw_cert, raw_key, nullb);

  unique_ptr<RpcTlsClient> tls_connection = force_unsigned ?
    make_unique<RpcTlsClient>(host, port, members_sni, nullptr, tls_cert) :
    make_unique<SigRpcTlsClient>(
      raw_key, host, port, members_sni, nullptr, tls_cert);

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

    if (*add_node)
    {
      const auto j_nodes = files::slurp_json(nodes_file);

      if (!j_nodes.is_array())
      {
        throw logic_error("Expected " + nodes_file + " to contain array");
      }

      for (auto node : j_nodes)
      {
        NodeInfo node_info = node;
        submit_add_node(*tls_connection, node_info);
      }
    }

    if (*add_code)
    {
      submit_accept_code(*tls_connection, new_code_id);
    }

    if (*accept_node)
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

    if (*removal)
    {
      submit_removal(*tls_connection, proposal_id);
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
      submit_ack(*tls_connection, raw_cert, raw_key);
    }

    if (*accept_recovery)
    {
      submit_accept_recovery(*tls_connection, sealed_secrets_file);
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
