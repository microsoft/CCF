// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/pem.h"
#include "ccf/crypto/verifier.h"
#include "ccf/node/node_configuration_interface.h"
#include "crypto/openssl/hash.h"
#include "ds/internal_logger.h"
#include "frontend_test_infra.h"
#include "kv/test/null_encryptor.h"
#include "nlohmann/json.hpp"
#include "node/http_node_client.h"
#include "node/internal_tables_access.h"
#include "node/rpc/node_frontend.h"
#include "node/rpc/self_cert_auth.h"
#include "node/startup_inputs.h"
#include "node_stub.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <latch>
#include <limits>
#include <thread>
#include <vector>

using namespace ccf;
using namespace nlohmann;

using TResponse = ::http::SimpleResponseProcessor::Response;

auto node_id = 0;

TResponse frontend_process(
  NodeRpcFrontend& frontend,
  const json& json_params,
  const std::string& path,
  const ccf::crypto::Pem& caller,
  llhttp_method method = HTTP_POST)
{
  ::http::Request r(path, method);
  const auto body = json_params.is_null() ? std::string() : json_params.dump();
  r.set_body(body);
  auto serialise_request = r.build_request();

  auto session =
    std::make_shared<ccf::SessionContext>(ccf::InvalidSessionId, caller.raw());
  auto rpc_ctx = ccf::make_rpc_context(session, serialise_request);
  frontend.process(rpc_ctx);

  CHECK(!rpc_ctx->response_is_pending);
  const auto serialised_response = rpc_ctx->serialise_response();

  ::http::SimpleResponseProcessor processor;
  ::http::ResponseParser parser(processor);

  parser.execute(serialised_response.data(), serialised_response.size());
  REQUIRE(processor.received.size() == 1);

  return processor.received.front();
}

class TestNodeRpcFrontend : public NodeRpcFrontend
{
public:
  using NodeRpcFrontend::NodeRpcFrontend;

  std::shared_ptr<ccf::RpcContextImpl> last_request;

  void process(std::shared_ptr<ccf::RpcContextImpl> ctx) override
  {
    NodeRpcFrontend::process(ctx);
    last_request = std::move(ctx);
  }

  ccf::endpoints::EndpointRegistry& get_node_endpoints()
  {
    return node_endpoints;
  }
};

class StubNodeConfiguration : public NodeConfigurationInterface
{
public:
  CCFConfig config = {};
  nlohmann::json node_data = nullptr;
  NodeConfigurationState state = {config, node_data, {}, true};

  const NodeConfigurationState& get() override
  {
    return state;
  }
};

void require_ledger_secrets_equal(
  const LedgerSecretsMap& first, const LedgerSecretsMap& second)
{
  REQUIRE(first.size() == second.size());
  REQUIRE(std::equal(
    first.begin(),
    first.end(),
    second.begin(),
    [](const auto& a, const auto& b) { return (*a.second == *b.second); }));
}

TEST_CASE("Node configuration retains operator file paths")
{
  const json input = {
    {"network", CCFConfig{}.network},
    {"node_data_json_file", "not-loaded/node.json"},
    {"service_data_json_file", "not-loaded/service.json"},
    {"tick_interval", "25ms"},
    {"memory", {{"max_msg_size", "128MB"}}},
    {"snapshots", {{"tx_count", 42}}},
    {"command",
     {{"type", "Start"},
      {"service_certificate_file", "not-loaded/service.pem"},
      {"start",
       {{"members",
         {{{"certificate_file", "not-loaded/member.pem"},
           {"encryption_public_key_file", "not-loaded/member_enc.pem"},
           {"data_json_file", "not-loaded/member.json"},
           {"recovery_role", MemberRecoveryRole::Owner}}}},
        {"constitution_files", {"not-loaded/first.js", "not-loaded/second.js"}},
        {"initial_service_certificate_validity_days", 7},
        {"service_subject_name", "CN=Configured Service"}}},
      {"join",
       {{"target_rpc_address", "localhost:1234"},
        {"retry_timeout", "2s"},
        {"follow_redirect", false},
        {"fetch_recent_snapshot", false},
        {"fetch_snapshot_max_attempts", 5},
        {"fetch_snapshot_retry_interval", "3s"},
        {"fetch_snapshot_max_size", "20MB"},
        {"host_data_transparent_statement_path", "not-loaded/statement.cose"}}},
      {"recover",
       {{"previous_service_identity_file", "not-loaded/previous.pem"},
        {"initial_service_certificate_validity_days", 13}}}}}};

  auto config = input.get<CCFConfig>();
  CHECK(config.command.type == StartType::Start);
  CHECK(
    config.command.start.members.front().certificate_file ==
    "not-loaded/member.pem");
  CHECK(
    config.command.start.members.front().recovery_role ==
    MemberRecoveryRole::Owner);
  CHECK(config.command.start.initial_service_certificate_validity_days == 7);
  CHECK(config.command.start.service_subject_name == "CN=Configured Service");
  CHECK(config.snapshots.tx_count == 42);
  CHECK(config.memory.max_msg_size.count_bytes() == 128 * 1024 * 1024);
  CHECK(config.tick_interval.count_ms() == 25);

  const json runtime_node_data = {{"name", "runtime node data"}};
  const NodeConfigurationState state{config, runtime_node_data, {}, false};
  CHECK(state.node_data == runtime_node_data);
  CHECK(state.node_config.node_data_json_file == "not-loaded/node.json");
  CHECK(state.node_config.service_data_json_file == "not-loaded/service.json");

  for (const auto type :
       {StartType::Start, StartType::Join, StartType::Recover})
  {
    config.command.type = type;
    const auto encoded = json(config);
    const auto decoded = encoded.get<CCFConfig>();
    CHECK(decoded.command.type == type);
    CHECK(decoded.command.start == config.command.start);
    CHECK(decoded.command.join == config.command.join);
    CHECK(decoded.command.recover == config.command.recover);
    CHECK(json(decoded) == encoded);
    CHECK_FALSE(encoded.contains("startup_host_time"));
    CHECK_FALSE(encoded.contains("start"));
    CHECK_FALSE(encoded.contains("node_data"));
  }

  CHECK(config.command.join.target_rpc_address == "localhost:1234");
  CHECK(config.command.join.retry_timeout.count_ms() == 2000);
  CHECK_FALSE(config.command.join.follow_redirect);
  CHECK_FALSE(config.command.join.fetch_recent_snapshot);
  CHECK(config.command.join.fetch_snapshot_max_attempts == 5);
  CHECK(config.command.join.fetch_snapshot_retry_interval.count_ms() == 3000);
  CHECK(
    config.command.join.fetch_snapshot_max_size.count_bytes() ==
    20 * 1024 * 1024);
  CHECK(
    config.command.join.host_data_transparent_statement_path ==
    "not-loaded/statement.cose");
  CHECK(
    config.command.recover.previous_service_identity_file ==
    "not-loaded/previous.pem");
  CHECK(config.command.recover.initial_service_certificate_validity_days == 13);

  const auto defaults = json{
    {"network", CCFConfig{}.network},
    {"command",
     {{"type", "Join"}}}}.get<CCFConfig>();
  CHECK(defaults.command.join.retry_timeout.count_ms() == 1000);
  CHECK(defaults.command.join.follow_redirect);
  CHECK(defaults.command.join.fetch_recent_snapshot);
  CHECK(
    defaults.command.recover.initial_service_certificate_validity_days == 1);
}

TEST_CASE("Genesis request retains resolved data on the wire")
{
  CreateNetworkNodeToNode::GenesisInfo genesis;
  genesis.members.emplace_back(member_cert);
  genesis.constitution = "export function validate() { return true; }";
  genesis.service_configuration.recovery_threshold = 1;

  const json encoded = genesis;
  CHECK(encoded.size() == 3);
  CHECK(encoded["members"] == json(genesis.members));
  CHECK(encoded["constitution"] == genesis.constitution);
  CHECK(
    encoded["service_configuration"] == json(genesis.service_configuration));
  CHECK(encoded.get<CreateNetworkNodeToNode::GenesisInfo>() == genesis);
}

namespace
{
  struct ScopedTempDir
  {
    std::filesystem::path path;

    ScopedTempDir()
    {
      auto pattern =
        (std::filesystem::temp_directory_path() / "ccf_startup_inputs_XXXXXX")
          .string();
      REQUIRE(mkdtemp(pattern.data()) != nullptr);
      path = pattern;
    }

    ~ScopedTempDir()
    {
      std::error_code ec;
      std::filesystem::remove_all(path, ec);
    }
  };

  std::string write_test_file(
    const ScopedTempDir& dir,
    const std::string& name,
    const std::string& contents)
  {
    const auto path = (dir.path / name).string();
    std::ofstream f(path, std::ios::binary);
    f << contents;
    f.close();
    REQUIRE(f.good());
    return path;
  }

  // This file is built with DOCTEST_CONFIG_NO_EXCEPTIONS_BUT_WITH_ALL_ASSERTS,
  // which compiles out the CHECK_THROWS assertions, so catch explicitly.
  template <typename F>
  std::string logic_error_message(const F& f)
  {
    try
    {
      f();
    }
    catch (const std::logic_error& e)
    {
      return e.what();
    }
    return "";
  }
}

TEST_CASE("Startup inputs are read from files")
{
  const ScopedTempDir dir;
  const auto encryption_key =
    ccf::crypto::make_rsa_key_pair()->public_key_pem();

  CCFConfig::Command::Start start;
  start.members.push_back(
    {write_test_file(dir, "member0_cert.pem", member_cert.str()),
     write_test_file(dir, "member0_enc_pubk.pem", encryption_key.str()),
     write_test_file(dir, "member0_data.json", R"({"is_operator": true})"),
     MemberRecoveryRole::Owner});
  start.members.push_back(
    {write_test_file(dir, "member1_cert.pem", member_cert.str())});
  start.constitution_files = {
    write_test_file(dir, "first.js", "first"),
    write_test_file(dir, "second.js", "second")};
  start.service_configuration.recovery_threshold = 1;

  const auto genesis = resolve_genesis_info(start);
  REQUIRE(genesis.members.size() == 2);
  CHECK(genesis.members[0].cert == member_cert);
  CHECK(genesis.members[0].encryption_pub_key == encryption_key);
  CHECK(genesis.members[0].member_data == json{{"is_operator", true}});
  CHECK(genesis.members[0].recovery_role == MemberRecoveryRole::Owner);
  CHECK(genesis.members[1].cert == member_cert);
  CHECK_FALSE(genesis.members[1].encryption_pub_key.has_value());
  CHECK(genesis.members[1].member_data.is_null());
  CHECK_FALSE(genesis.members[1].recovery_role.has_value());
  CHECK(genesis.constitution == "first\nsecond");
  CHECK(genesis.service_configuration == start.service_configuration);

  {
    INFO("Empty member data is rejected, empty node or service data is null");
    const auto empty_file = write_test_file(dir, "empty.json", "");
    CHECK(read_startup_json(empty_file, "service data", true).is_null());
    auto empty_member_data = start;
    empty_member_data.members[0].data_json_file = empty_file;
    CHECK(
      logic_error_message([&]() { resolve_genesis_info(empty_member_data); })
        .starts_with(
          fmt::format("Could not parse member data from {}:", empty_file)));
  }

  {
    INFO("Malformed JSON names the input");
    const auto malformed_file = write_test_file(dir, "malformed.json", "{");
    CHECK(logic_error_message(
            [&]() { read_startup_json(malformed_file, "node data", true); })
            .starts_with(fmt::format(
              "Could not parse node data from {}:", malformed_file)));
  }

  {
    INFO("Missing or unreadable files name the input");
    const auto missing_file = (dir.path / "missing.pem").string();
    CHECK(
      logic_error_message(
        [&]() { read_startup_file(missing_file, "service certificate"); }) ==
      fmt::format("Could not read service certificate from {}", missing_file));
    CHECK(
      logic_error_message(
        [&]() { read_startup_file(dir.path.string(), "constitution"); }) ==
      fmt::format("Could not read constitution from {}", dir.path.string()));
    auto missing_constitution = start;
    missing_constitution.constitution_files.push_back(missing_file);
    CHECK(
      logic_error_message([&]() {
        resolve_genesis_info(missing_constitution);
      }) == fmt::format("Could not read constitution from {}", missing_file));
  }
}

TEST_CASE("Startup inputs are resolved by start type")
{
  const ScopedTempDir dir;
  const auto missing_file = (dir.path / "missing").string();
  const auto bytes = [](const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
  };
  const auto resolve = [](const CCFConfig& config, StartType type) {
    StartupInputs inputs;
    const auto error = logic_error_message(
      [&]() { inputs = resolve_startup_inputs(config, type); });
    CHECK(error == "");
    return inputs;
  };

  CCFConfig config;
  config.node_data_json_file =
    write_test_file(dir, "node_data.json", R"({"node": 1})");
  config.service_data_json_file =
    write_test_file(dir, "service_data.json", R"({"service": 2})");
  config.command.service_certificate_file =
    write_test_file(dir, "service_cert.pem", "service certificate");
  config.command.start.members.push_back(
    {write_test_file(dir, "member_cert.pem", member_cert.str())});
  config.command.start.constitution_files = {
    write_test_file(dir, "constitution.js", "constitution")};
  config.command.recover.previous_service_identity_file =
    write_test_file(dir, "previous_identity.pem", "previous identity");

  {
    INFO("Start reads node data, service data and genesis inputs");
    const auto inputs = resolve(config, StartType::Start);
    CHECK(inputs.node_data == json{{"node", 1}});
    CHECK(inputs.service_data == json{{"service", 2}});
    REQUIRE(inputs.genesis_info.has_value());
    CHECK(inputs.genesis_info->members.size() == 1);
    CHECK(inputs.genesis_info->constitution == "constitution");
    CHECK(inputs.join_service_cert.empty());
    CHECK_FALSE(inputs.previous_service_identity.has_value());
  }

  {
    INFO("Recover reads node data, service data and the previous identity");
    const auto inputs = resolve(config, StartType::Recover);
    CHECK(inputs.node_data == json{{"node", 1}});
    CHECK(inputs.service_data == json{{"service", 2}});
    CHECK_FALSE(inputs.genesis_info.has_value());
    CHECK(inputs.join_service_cert.empty());
    CHECK(inputs.previous_service_identity == bytes("previous identity"));
  }

  {
    INFO("Join reads node data and the service certificate only");
    auto join_config = config;
    join_config.service_data_json_file = missing_file;
    join_config.command.start.constitution_files = {missing_file};
    join_config.command.recover.previous_service_identity_file = missing_file;
    const auto inputs = resolve(join_config, StartType::Join);
    CHECK(inputs.node_data == json{{"node", 1}});
    CHECK(inputs.service_data.is_null());
    CHECK_FALSE(inputs.genesis_info.has_value());
    CHECK(inputs.join_service_cert == bytes("service certificate"));
    CHECK_FALSE(inputs.previous_service_identity.has_value());
  }

  {
    INFO("Inputs required by the start type must be readable");
    auto no_identity = config;
    no_identity.command.recover.previous_service_identity_file = "";
    CHECK(
      logic_error_message(
        [&]() { resolve_startup_inputs(no_identity, StartType::Recover); }) ==
      "Recovery requires the certificate of the previous service identity");

    auto no_service_cert = config;
    no_service_cert.command.service_certificate_file = missing_file;
    CHECK(
      logic_error_message(
        [&]() { resolve_startup_inputs(no_service_cert, StartType::Join); }) ==
      fmt::format("Could not read service certificate from {}", missing_file));

    auto no_service_data = config;
    no_service_data.service_data_json_file = missing_file;
    for (const auto type : {StartType::Start, StartType::Recover})
    {
      CHECK(
        logic_error_message([&]() {
          resolve_startup_inputs(no_service_data, type);
        }) == fmt::format("Could not read service data from {}", missing_file));
    }

    auto no_node_data = config;
    no_node_data.node_data_json_file = missing_file;
    for (const auto type :
         {StartType::Start, StartType::Join, StartType::Recover})
    {
      CHECK(
        logic_error_message([&]() {
          resolve_startup_inputs(no_node_data, type);
        }) == fmt::format("Could not read node data from {}", missing_file));
    }
  }
}

TEST_CASE("Self certificate authentication")
{
  NetworkState network;
  auto tx = network.tables->create_tx();
  StubNodeContext context;
  SelfCertAuthnPolicy policy(context);
  CHECK(policy.get_security_scheme_name() == "self_cert");

  const auto self_kp = ccf::crypto::make_ec_key_pair();
  const auto self_cert = self_kp->self_sign("CN=Self", valid_from, valid_to);
  const auto self_der = ccf::crypto::make_verifier(self_cert)->cert_der();
  std::string error_reason;
  const auto authenticate = [&](const std::vector<uint8_t>& cert) {
    error_reason.clear();
    auto session =
      std::make_shared<ccf::SessionContext>(ccf::InvalidSessionId, cert);
    ::http::Request request("/node/create", HTTP_POST);
    auto rpc_ctx = ccf::make_rpc_context(session, request.build_request());
    return policy.authenticate(tx, rpc_ctx, error_reason);
  };

  CHECK(authenticate(self_der) == nullptr);
  CHECK(error_reason == "Only the node itself can call this endpoint.");

  context.node_id = ccf::compute_node_id_from_kp(self_kp);
  CHECK(!tx.ro(network.nodes)->has(context.node_id));
  const auto identity = authenticate(self_der);
  REQUIRE(identity != nullptr);
  const auto* cert_identity =
    dynamic_cast<const AnyCertAuthnIdentity*>(identity.get());
  REQUIRE(cert_identity != nullptr);
  CHECK(cert_identity->cert == self_der);
  CHECK(error_reason.empty());

  CHECK(authenticate(self_cert.raw()) != nullptr);

  const auto issuer = make_test_network_ident();
  const auto endorsed_cert = ccf::crypto::create_endorsed_cert(
    self_kp->create_csr("CN=Self"),
    valid_from,
    valid_to,
    issuer->priv_key,
    issuer->cert);
  CHECK(authenticate(endorsed_cert.raw()) != nullptr);

  const auto other_kp = ccf::crypto::make_ec_key_pair();
  const auto other_cert = other_kp->self_sign("CN=Self", valid_from, valid_to);
  CHECK(authenticate(other_cert.raw()) == nullptr);
  CHECK(error_reason == "Only the node itself can call this endpoint.");

  NodeInfo other_node;
  other_node.status = NodeStatus::TRUSTED;
  tx.rw(network.nodes)->put(ccf::compute_node_id_from_kp(other_kp), other_node);
  CHECK(authenticate(other_cert.raw()) == nullptr);
  CHECK(error_reason == "Only the node itself can call this endpoint.");

  CHECK(authenticate({}) == nullptr);
  CHECK(error_reason == "No caller certificate");

  const auto expired_cert =
    self_kp->self_sign("CN=Self", "20200101000000Z", "20200102000000Z");
  CHECK(authenticate(expired_cert.raw()) == nullptr);
  CHECK(error_reason.contains("after certificate's Not After"));

  const auto future_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now() + 24h);
  const auto future_cert = self_kp->self_sign(
    "CN=Self",
    future_from,
    ccf::crypto::compute_cert_valid_to_string(future_from, 1));
  CHECK(authenticate(future_cert.raw()) == nullptr);
  CHECK(error_reason.contains("before certificate's Not Before"));
}

TEST_CASE("Pending-node cleanup uses renewed client certificates")
{
  NetworkState network;
  network.tables->set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  StubNodeContext context;
  context.install_subsystem(std::make_shared<StubNodeConfiguration>());

  const auto self_kp = ccf::crypto::make_ec_key_pair();
  context.node_id = ccf::compute_node_id_from_kp(self_kp);
  auto node_cert =
    self_kp->self_sign("CN=Self", "20200101000000Z", "20200102000000Z");

  const auto pending_node_id =
    ccf::compute_node_id_from_kp(ccf::crypto::make_ec_key_pair());
  {
    auto tx = network.tables->create_tx();
    NodeInfo pending_node;
    pending_node.encryption_pub_key = dummy_enc_pubk;
    pending_node.status = NodeStatus::PENDING;
    pending_node.pending_last_seen = 0;
    tx.rw(network.nodes)->put(pending_node_id, pending_node);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  auto frontend = std::make_shared<TestNodeRpcFrontend>(network, context);
  frontend->open();
  auto rpc_map = std::make_shared<ccf::RPCMap>();
  rpc_map->register_frontend<ccf::ActorsType::nodes>(frontend);
  HTTPNodeClient client(rpc_map, self_kp, [&]() { return node_cert; });

  ::http::Request request(
    "/node/network/nodes/remove_expired_pending", HTTP_POST);
  request.set_header(ccf::http::headers::CONTENT_LENGTH, "0");
  CHECK_FALSE(client.make_request(request));
  REQUIRE(frontend->last_request != nullptr);
  CHECK(
    frontend->last_request->get_response_status() == HTTP_STATUS_UNAUTHORIZED);
  {
    auto tx = network.tables->create_tx();
    CHECK(tx.ro(network.nodes)->has(pending_node_id));
  }

  node_cert = self_kp->self_sign("CN=Self", valid_from, valid_to);
  const auto success = client.make_request(request);
  const auto response = frontend->last_request->serialise_response();
  INFO(std::string(response.begin(), response.end()));
  REQUIRE(success);
  {
    auto tx = network.tables->create_tx();
    CHECK_FALSE(tx.ro(network.nodes)->has(pending_node_id));
  }
}

TEST_CASE("Add a node to an opening service")
{
  NetworkState network;
  auto tx_encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(tx_encryptor);
  auto gen_tx = network.tables->create_tx();
  InternalTablesAccess::init_configuration(
    gen_tx, {0, ConsensusType::CFT, std::nullopt});

  network.identity = make_test_network_ident();
  network.ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  network.ledger_secrets->init();

  StubNodeContext context;
  NodeRpcFrontend frontend(network, context);
  frontend.open();

  // New node should not be given ledger secret past this one via join request
  ccf::kv::Version up_to_ledger_secret_seqno = 4;
  network.ledger_secrets->set_secret(
    up_to_ledger_secret_seqno, make_ledger_secret());

  // Node certificate
  ccf::crypto::ECKeyPairPtr node_kp = ccf::crypto::make_ec_key_pair();
  const auto caller = node_kp->self_sign("CN=Joiner", valid_from, valid_to);
  const auto node_public_encryption_key =
    ccf::crypto::make_ec_key_pair()->public_key_pem();

  INFO("Add first node before a service exists");
  {
    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;
    const auto response =
      frontend_process(frontend, join_input, "join", caller);

    check_error(response, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    check_error_message(response, "No service is available to accept new node");
  }

  InternalTablesAccess::create_service(
    gen_tx, network.identity->cert, ccf::TxID{2, 1});
  REQUIRE(gen_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  auto tx = network.tables->create_tx();

  INFO("Add first node which should be trusted straight away");
  {
    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;
    // Join input does not include CSR (1.x)
    join_input.certificate_signing_request = std::nullopt;

    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.network_info.has_value());
    CHECK(response.network_info->identity == *network.identity.get());
    CHECK(response.network_info->public_only == false);
    // No endorsed certificate since no CSR was passed in
    CHECK(response.network_info->endorsed_certificate == std::nullopt);

    auto pk_der = node_kp->public_key_der();
    const NodeId joiner_node_id = ccf::crypto::Sha256Hash(pk_der).hex_str();
    auto nodes = tx.rw(network.nodes);
    auto node_info = nodes->get(joiner_node_id);

    CHECK(node_info.has_value());
    CHECK(node_info->status == NodeStatus::TRUSTED);
    CHECK(node_kp->public_key_pem() == node_info->public_key);
  }

  INFO("Adding the same node should return the same result");
  {
    // Even if rekey occurs in between, the same ledger secrets should be
    // returned
    network.ledger_secrets->set_secret(
      up_to_ledger_secret_seqno + 1, make_ledger_secret());

    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;

    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.network_info.has_value());
    require_ledger_secrets_equal(
      response.network_info->ledger_secrets,
      network.ledger_secrets->get(tx, up_to_ledger_secret_seqno));
    CHECK(response.network_info->identity == *network.identity.get());
  }

  INFO(
    "Adding a different node with the same node network details should fail");
  {
    ccf::crypto::ECKeyPairPtr other_kp = ccf::crypto::make_ec_key_pair();
    auto v = ccf::crypto::make_verifier(
      other_kp->self_sign("CN=Other Joiner", valid_from, valid_to));
    const auto new_caller = v->cert_pem();

    // Network node info is empty (same as before)
    JoinNetworkNodeToNode::In join_input;
    join_input.public_encryption_key = node_public_encryption_key;

    auto http_response =
      frontend_process(frontend, join_input, "join", new_caller);

    check_error(http_response, HTTP_STATUS_BAD_REQUEST);
    check_error_message(
      http_response, "A node with the same published node address");
  }
}

TEST_CASE("JWT refresh metrics are thread-safe")
{
  NetworkState network;
  StubNodeContext context;
  TestNodeRpcFrontend frontend(network, context);
  frontend.open();

  constexpr size_t worker_count = 4;
  constexpr size_t iterations = 1'000;
  std::latch start(worker_count);
  std::vector<std::thread> workers;
  workers.reserve(worker_count);

  const ccf::endpoints::RequestCompletedEvent successful_refresh{
    "POST", "/jwt_keys/refresh", HTTP_STATUS_OK};
  const ccf::endpoints::RequestCompletedEvent failed_refresh{
    "POST", "/jwt_keys/refresh", HTTP_STATUS_INTERNAL_SERVER_ERROR};

  auto& node_endpoints = frontend.get_node_endpoints();
  for (size_t i = 0; i < worker_count; ++i)
  {
    workers.emplace_back([&]() {
      start.arrive_and_wait();
      for (size_t j = 0; j < iterations; ++j)
      {
        node_endpoints.handle_event_request_completed(successful_refresh);
        node_endpoints.handle_event_request_completed(failed_refresh);
      }
    });
  }

  for (auto& worker : workers)
  {
    worker.join();
  }

  const auto response = frontend_process(
    frontend, json(), "jwt_keys/refresh/metrics", member_cert, HTTP_GET);
  REQUIRE(response.status == HTTP_STATUS_OK);

  const auto metrics = parse_response_body<JWTRefreshMetrics>(response);
  CHECK(metrics.attempts == worker_count * iterations * 2);
  CHECK(metrics.successes == worker_count * iterations);
  CHECK(metrics.failures == worker_count * iterations);
}

TEST_CASE("Add a node to an open service")
{
  NetworkState network;
  auto gen_tx = network.tables->create_tx();
  auto tx_encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(tx_encryptor);

  network.identity = make_test_network_ident();
  network.ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  network.ledger_secrets->init();

  StubNodeContext context;
  context.node_operation->is_public = true;
  auto node_configuration = std::make_shared<StubNodeConfiguration>();
  context.install_subsystem(node_configuration);
  NodeRpcFrontend frontend(network, context);
  frontend.open();

  // New node should not be given ledger secret past this one via join request
  ccf::kv::Version up_to_ledger_secret_seqno = 4;
  network.ledger_secrets->set_secret(
    up_to_ledger_secret_seqno, make_ledger_secret());

  InternalTablesAccess::create_service(
    gen_tx, network.identity->cert, ccf::TxID{2, 1});
  InternalTablesAccess::init_configuration(gen_tx, {1});
  InternalTablesAccess::activate_member(
    gen_tx,
    InternalTablesAccess::add_member(
      gen_tx,
      {member_cert, ccf::crypto::make_rsa_key_pair()->public_key_pem()}));
  REQUIRE(InternalTablesAccess::open_service(gen_tx));
  REQUIRE(InternalTablesAccess::endorse_previous_identity(
    gen_tx, *network.identity->get_key_pair()));
  REQUIRE(gen_tx.commit() == ccf::kv::CommitResult::SUCCESS);

  // Node certificate
  ccf::crypto::ECKeyPairPtr node_kp = ccf::crypto::make_ec_key_pair();
  const auto caller = node_kp->self_sign("CN=Joiner", valid_from, valid_to);

  const auto node_public_encryption_key =
    ccf::crypto::make_ec_key_pair()->public_key_pem();

  JoinNetworkNodeToNode::In join_input;
  join_input.public_encryption_key = node_public_encryption_key;
  join_input.certificate_signing_request = node_kp->create_csr("CN=Joiner");

  INFO("Add node once service is open");
  {
    auto tx = network.tables->create_tx();
    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    CHECK(!response.network_info.has_value());

    auto pk_der = node_kp->public_key_der();
    const NodeId joiner_node_id = ccf::crypto::Sha256Hash(pk_der).hex_str();
    auto nodes = tx.rw(network.nodes);
    auto node_info = nodes->get(joiner_node_id);
    CHECK(node_info.has_value());
    CHECK(node_info->status == NodeStatus::PENDING);
    CHECK(node_kp->public_key_pem() == node_info->public_key);
  }

  INFO(
    "Adding a different node with the same node network details should fail");
  {
    ccf::crypto::ECKeyPairPtr other_kp = ccf::crypto::make_ec_key_pair();
    auto v = ccf::crypto::make_verifier(
      other_kp->self_sign("CN=Joiner", valid_from, valid_to));
    const auto new_caller = v->cert_pem();

    // Network node info is empty (same as before)
    JoinNetworkNodeToNode::In other_join_input;
    other_join_input.public_encryption_key = node_public_encryption_key;

    auto http_response =
      frontend_process(frontend, other_join_input, "join", new_caller);

    check_error(http_response, HTTP_STATUS_BAD_REQUEST);
    check_error_message(
      http_response, "A node with the same published node address");
  }

  INFO("Try to join again without being trusted");
  {
    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    // The network secrets are still not available to the joining node
    CHECK(!response.network_info.has_value());
  }

  INFO("Trust node and attempt to join");
  {
    auto tx = network.tables->create_tx();
    // In a real scenario, nodes are trusted via member governance.
    auto joining_node_id = ccf::compute_node_id_from_kp(node_kp);
    InternalTablesAccess::trust_node(
      tx, joining_node_id, network.ledger_secrets->get_latest(tx).first);
    const auto dummy_endorsed_certificate =
      ccf::crypto::make_ec_key_pair()->self_sign(
        "CN=dummy endorsed certificate", valid_from, valid_to);
    auto endorsed_certificate = tx.rw(network.node_endorsed_certificates);
    endorsed_certificate->put(joining_node_id, {dummy_endorsed_certificate});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    // In the meantime, a new ledger secret is added. The new ledger secret
    // should not be passed to the new joiner via the join
    network.ledger_secrets->set_secret(
      up_to_ledger_secret_seqno + 1, make_ledger_secret());

    auto http_response = frontend_process(frontend, join_input, "join", caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    const auto response =
      parse_response_body<JoinNetworkNodeToNode::Out>(http_response);

    auto verify_tx = network.tables->create_tx();
    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.network_info.has_value());
    require_ledger_secrets_equal(
      response.network_info->ledger_secrets,
      network.ledger_secrets->get(verify_tx, up_to_ledger_secret_seqno));
    CHECK(response.network_info->identity == *network.identity.get());
    CHECK(response.node_status == NodeStatus::TRUSTED);
    CHECK(response.network_info->public_only == true);
    CHECK(response.network_info->endorsed_certificate.has_value());
    CHECK(
      response.network_info->endorsed_certificate.value() ==
      dummy_endorsed_certificate);
  }

  INFO("Expired Pending nodes are removed");
  {
    const auto self_kp = ccf::crypto::make_ec_key_pair();
    const auto self_caller =
      self_kp->self_sign("CN=Self", valid_from, valid_to);
    context.node_id = ccf::compute_node_id_from_kp(self_kp);

    CHECK(
      std::chrono::milliseconds(CCFConfig{}.pending_node_timeout) ==
      std::chrono::hours(1));

    ccf::crypto::ECKeyPairPtr expired_node_kp = ccf::crypto::make_ec_key_pair();
    const auto expired_node_caller =
      expired_node_kp->self_sign("CN=Expired Joiner", valid_from, valid_to);
    const auto expired_node_id = ccf::compute_node_id_from_kp(expired_node_kp);

    JoinNetworkNodeToNode::In expired_join_input;
    expired_join_input.public_encryption_key =
      ccf::crypto::make_ec_key_pair()->public_key_pem();
    expired_join_input.certificate_signing_request =
      expired_node_kp->create_csr("CN=Expired Joiner");
    expired_join_input.node_info_network.node_to_node_interface
      .published_address = "localhost:1234";

    auto http_response = frontend_process(
      frontend, expired_join_input, "join", expired_node_caller);
    CHECK(http_response.status == HTTP_STATUS_OK);

    {
      auto verify_tx = network.tables->create_tx();
      auto nodes = verify_tx.ro(network.nodes);
      const auto node_info = nodes->get(expired_node_id);
      REQUIRE(node_info.has_value());
      REQUIRE(node_info->pending_last_seen.has_value());

      nlohmann::json node_info_json = node_info.value();
      CHECK(
        node_info_json.get<NodeInfo>().pending_last_seen ==
        node_info->pending_last_seen);
      node_info_json.erase("pending_last_seen");
      CHECK(!node_info_json.get<NodeInfo>().pending_last_seen.has_value());
    }

    const auto get_node = [&](const NodeId& id) {
      auto verify_tx = network.tables->create_tx();
      const auto node_info = verify_tx.ro(network.nodes)->get(id);
      REQUIRE(node_info.has_value());
      return node_info.value();
    };
    const auto now_ms = []() {
      return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
    };
    const auto set_last_seen =
      [&](const NodeId& id, std::optional<int64_t> last_seen) {
        auto age_tx = network.tables->create_tx();
        auto nodes = age_tx.rw(network.nodes);
        auto node_info = nodes->get(id);
        REQUIRE(node_info.has_value());
        node_info->pending_last_seen = last_seen;
        nodes->put(id, node_info.value());
        REQUIRE(age_tx.commit() == ccf::kv::CommitResult::SUCCESS);
      };
    const auto cleanup = [&]() {
      const auto response = frontend_process(
        frontend, nullptr, "network/nodes/remove_expired_pending", self_caller);
      REQUIRE(response.status == HTTP_STATUS_OK);
      CHECK(!response.headers.contains(ccf::http::headers::LOCATION));
    };

    for (const auto timestamp :
         {std::optional<int64_t>{},
          std::optional<int64_t>{-1},
          std::optional<int64_t>{std::numeric_limits<int64_t>::max()}})
    {
      set_last_seen(expired_node_id, timestamp);
      const auto before = now_ms();
      cleanup();
      const auto last_seen = get_node(expired_node_id).pending_last_seen;
      REQUIRE(last_seen.has_value());
      CHECK(last_seen.value() >= before);
      CHECK(last_seen.value() <= now_ms());
    }

    const auto stale_pending_last_seen = now_ms() -
      std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::minutes(31))
        .count();
    set_last_seen(expired_node_id, stale_pending_last_seen);

    auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
    consensus->state = ccf::kv::test::StubConsensus::Backup;
    frontend.set_consensus_and_history(consensus.get(), nullptr);
    context.node_operation->can_replicate_result = false;

    http_response = frontend_process(
      frontend, expired_join_input, "join", expired_node_caller);
    CHECK(http_response.status != HTTP_STATUS_OK);
    CHECK(
      get_node(expired_node_id).pending_last_seen == stale_pending_last_seen);

    cleanup();
    CHECK(
      get_node(expired_node_id).pending_last_seen == stale_pending_last_seen);

    consensus->state = ccf::kv::test::StubConsensus::Primary;
    context.node_operation->can_replicate_result = true;
    const auto before_retry = now_ms();
    http_response = frontend_process(
      frontend, expired_join_input, "join", expired_node_caller);
    CHECK(http_response.status == HTTP_STATUS_OK);
    const auto refreshed = get_node(expired_node_id).pending_last_seen;
    REQUIRE(refreshed.has_value());
    CHECK(refreshed.value() >= before_retry);
    CHECK(refreshed.value() <= now_ms());
    cleanup();
    CHECK(get_node(expired_node_id).pending_last_seen == refreshed);

    const auto expired = now_ms() -
      std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::hours(2))
        .count();
    const auto trusted_node_id = ccf::compute_node_id_from_kp(node_kp);
    set_last_seen(expired_node_id, expired);
    set_last_seen(trusted_node_id, expired);

    for (const auto timeout : {"0s", "1h"})
    {
      node_configuration->config.pending_node_timeout = {timeout};
      for (const auto& other_caller : {caller, expired_node_caller})
      {
        const auto response = frontend_process(
          frontend,
          nullptr,
          "network/nodes/remove_expired_pending",
          other_caller);
        CHECK(response.status == HTTP_STATUS_UNAUTHORIZED);
        check_error_message(
          response, "Only the node itself can call this endpoint.");
        CHECK(get_node(expired_node_id).pending_last_seen == expired);
        CHECK(get_node(trusted_node_id).pending_last_seen == expired);
      }
    }

    node_configuration->config.pending_node_timeout = {"0s"};
    cleanup();
    CHECK(get_node(expired_node_id).pending_last_seen == expired);
    CHECK(get_node(expired_node_id).status == NodeStatus::PENDING);

    node_configuration->config.pending_node_timeout = {"1h"};
    cleanup();
    {
      auto verify_tx = network.tables->create_tx();
      CHECK(!verify_tx.ro(network.nodes)->has(expired_node_id));
    }
    CHECK(get_node(trusted_node_id).status == NodeStatus::TRUSTED);
    CHECK(get_node(trusted_node_id).pending_last_seen == expired);
  }
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
