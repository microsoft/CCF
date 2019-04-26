// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "crypto/hash.h"
#include "ds/files.h"
#include "node/entities.h"
#include "node/members.h"
#include "node/proposals.h"
#include "node/rpc/jsonrpc.h"
#include "node/script.h"
#include "rpc_tls_client.h"
#include "sig_rpc_tls_client.h"
#include "tls/keypair.h"

#include <CLI11/CLI11.hpp>

using namespace ccf;
using namespace files;
using namespace jsonrpc;
using namespace std;
using namespace nlohmann;

constexpr auto members_sni = "members";

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

void display(const json& proposals)
{
  for (auto it = proposals.begin(); it != proposals.end(); ++it)
  {
    cout << "------ Proposal ------" << endl;
    cout << "-- Proposal id: " << it.key() << endl;
    OpenProposal op = it.value();
    cout << "-- Proposer id: " << op.proposer << endl;
    cout << "-- Script: " << json(op.script) << endl;
    cout << "-- Parameter: " << op.parameter << endl;
    cout << "-- Votes: " << json(op.votes) << endl;
    cout << "----------------------" << endl;
    cout << endl;
  }
}

void add_new(
  RpcTlsClient& tls_connection, const string& cert_file, const string& proposal)
{
  const auto cert = slurp(cert_file);
  const auto params =
    proposal_params(proposal, tls::Verifier(cert).raw_cert_data());
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
  cout << "Displaying all pending proposals: " << endl;
  cout << endl;
  display(response.result);
}

void submit_ack(
  RpcTlsClient& tls_connection,
  const vector<uint8_t>& raw_cert,
  const vector<uint8_t>& raw_key)
{
  // member using its own certificate reads its member id
  tls::Verifier verifier(raw_cert);
  Response<ObjectId> read_id = json::from_msgpack(tls_connection.call(
    "read", read_params(verifier.raw_cert_data(), "membercerts")));
  const auto member_id = read_id.result;

  // member reads nonce
  Response<MemberAck> read_ack = json::from_msgpack(
    tls_connection.call("read", read_params(member_id, "memberacks")));

  // member signs nonce and sends ack
  tls::KeyPair kp(raw_key);
  const auto sig = kp.sign_hash(crypto::Sha256Hash{read_ack.result.next_nonce});
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

  bool sign = false;
  app.add_flag("--sign", sign, "Send client-signed transactions");

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
  vote->add_option("--id", proposal_id, "The proposal id")->required(true);
  vote->add_flag("--accept", accept, "Accept the proposal");
  vote->add_flag("--reject", reject, "Reject the proposal");

  string query_file;
  auto query = app.add_subcommand("query", "Submit a query");
  query->add_option("--script", query_file, "Query lua script")
    ->required(true)
    ->check(CLI::ExistingFile);

  auto ack =
    app.add_subcommand("ack", "Acknowledge self added into the network");

  NodeId node_id;
  auto accept_node = app.add_subcommand("accept_node", "Make a node trusted");
  accept_node->add_option("--id", node_id, "The node id")->required(true);

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

  unique_ptr<RpcTlsClient> tls_connection = sign ?
    make_unique<SigRpcTlsClient>(
      raw_key, host, port, members_sni, nullptr, tls_cert) :
    make_unique<RpcTlsClient>(host, port, members_sni, nullptr, tls_cert);

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

    if (*accept_node)
    {
      submit_accept_node(*tls_connection, node_id);
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
