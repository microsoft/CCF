// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/recovery_decision_protocol.h"

#include "ccf/crypto/pem.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/x509_time_fmt.h"
#include "ccf/node_context.h"
#include "ccf/odata_error.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/self_healing_open.h"
#include "ccf/service/tables/service.h"
#include "crypto/openssl/ec_key_pair.h"
#include "crypto/openssl/mldsa_support.h"
#include "ds/internal_logger.h"
#include "http/http_builder.h"
#include "http/http_parser.h"
#include "http_client/curl.h"
#include "kv/null_encryptor.h"
#include "kv/test/null_tx_history.h"
#include "kv/test/stub_consensus.h"
#include "node/node_configuration_subsystem.h"
#include "node/node_state.h"
#include "node/rpc/node_frontend.h"
#include "node/rpc/node_operation.h"
#include "node/rpc/test/node_stub.h"
#include "tasks/task_system.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <chrono>
#include <cstdlib>
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <uv.h>
#include <vector>

namespace ccf
{
  struct RecoveryDecisionProtocolTestAccess
  {
    static void set_config(NodeState& ns, const CCFConfig& cfg)
    {
      ns.config = cfg;
    }

    static void clear_sealing_recovery(NodeState& ns)
    {
      ns.config.sealing_recovery = std::nullopt;
    }

    static void clear_rdp_config(NodeState& ns)
    {
      REQUIRE(ns.config.sealing_recovery.has_value());
      if (ns.config.sealing_recovery.has_value())
      {
        ns.config.sealing_recovery->recovery_decision_protocol = std::nullopt;
      }
    }

    static void set_consensus(
      NodeState& ns, std::shared_ptr<ccf::kv::Consensus> consensus)
    {
      ns.consensus = std::move(consensus);
    }

    static void set_last_recovered_signed_idx(
      NodeState& ns, ::consensus::Index idx)
    {
      ns.last_recovered_signed_idx = idx;
    }

    static void set_self_signed_cert(
      NodeState& ns, const ccf::crypto::Pem& cert)
    {
      std::lock_guard<ds::Mutex> guard(ns.node_certificates_lock);
      ns.self_signed_node_cert = cert;
    }

    static std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> get_sign_kp(
      NodeState& ns)
    {
      return ns.node_sign_kp;
    }
  };
}

namespace
{
  using namespace ccf;
  using namespace ccf::recovery_decision_protocol;
  using namespace std::chrono_literals;
  using TResponse = ::http::SimpleResponseProcessor::Response;

  ccf::crypto::Pem make_self_signed_cert(
    const ccf::crypto::ECKeyPairPtr& kp, const std::string& subject)
  {
    const auto valid_from =
      ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
    const auto valid_to =
      ccf::crypto::compute_cert_valid_to_string(valid_from, 365);
    return kp->self_sign(subject, valid_from, valid_to);
  }

  std::unique_ptr<ccf::NetworkIdentity> make_network_identity()
  {
    const auto valid_from =
      ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
    return std::make_unique<ccf::NetworkIdentity>(
      "CN=CCF test service",
      ccf::crypto::service_identity_curve_choice,
      ccf::crypto::MLDSAParameterSet::ML_DSA_65,
      valid_from,
      2);
  }

  class StubRuntimeControl : public ccf::AbstractRuntimeControl
  {
  public:
    size_t restart_count = 0;

    void report_stopped() override {}

    void report_fatal_error(const std::string& /*message*/) override {}

    void request_restart() override
    {
      ++restart_count;
    }
  };

  class ConfigurableNodeOperation : public ccf::NodeOperation
  {
  public:
    std::optional<QuoteVerificationResult> verify_quote_override =
      QuoteVerificationResult::Verified;
    std::optional<std::optional<ccf::NodeId>> primary_override = std::nullopt;
    bool throw_on_rdp = false;

    using ccf::NodeOperation::NodeOperation;

    QuoteVerificationResult verify_quote(
      ccf::kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der,
      pal::PlatformAttestationMeasurement& measurement,
      const std::optional<std::vector<uint8_t>>& code_transparent_statement,
      std::shared_ptr<NetworkIdentitySubsystemInterface>
        network_identity_subsystem) override
    {
      if (verify_quote_override.has_value())
      {
        return verify_quote_override.value();
      }
      return ccf::NodeOperation::verify_quote(
        tx,
        quote_info,
        expected_node_public_key_der,
        measurement,
        code_transparent_statement,
        network_identity_subsystem);
    }

    std::optional<ccf::NodeId> get_primary() override
    {
      if (primary_override.has_value())
      {
        return primary_override.value();
      }
      return ccf::NodeOperation::get_primary();
    }

    RecoveryDecisionProtocolSubsystem& recovery_decision_protocol() override
    {
      if (throw_on_rdp)
      {
        throw std::logic_error("Simulated protocol failure");
      }
      return ccf::NodeOperation::recovery_decision_protocol();
    }
  };

  class TestNodeContext : public ccf::AbstractNodeContext
  {
  public:
    ccf::NodeId node_id;

    explicit TestNodeContext(ccf::NodeId id) : node_id(std::move(id))
    {
      install_subsystem(std::make_shared<StubNodeStateCache>());
    }

    [[nodiscard]] ccf::NodeId get_node_id() const override
    {
      return node_id;
    }
  };

  class RecoveryHandlersEndpoints : public ccf::CommonEndpointRegistry
  {
  public:
    explicit RecoveryHandlersEndpoints(ccf::AbstractNodeContext& context_) :
      ccf::CommonEndpointRegistry(get_actor_prefix(ActorsType::nodes), context_)
    {}

    void init_handlers() override
    {
      ccf::node::init_recovery_decision_protocol_handlers(*this, this->context);
    }
  };

  class RecoveryHandlersFrontend : public RpcFrontend
  {
  private:
    RecoveryHandlersEndpoints endpoints;

  public:
    RecoveryHandlersFrontend(
      NetworkState& network_, ccf::AbstractNodeContext& context_) :
      RpcFrontend(*network_.tables, endpoints, context_),
      endpoints(context_)
    {}
  };

  void drain_main_job_board()
  {
    auto& board = ccf::tasks::get_main_job_board();
    while (auto task = board.get_task())
    {
      task->cancel_task();
    }
  }

  std::vector<ccf::tasks::Task> collect_ready_tasks()
  {
    auto& board = ccf::tasks::get_main_job_board();
    std::vector<ccf::tasks::Task> tasks;
    while (auto task = board.get_task())
    {
      tasks.push_back(std::move(task));
    }
    return tasks;
  }

  ccf::tasks::Task take_named_task(
    std::vector<ccf::tasks::Task>& tasks, const std::string& name)
  {
    for (auto it = tasks.begin(); it != tasks.end(); ++it)
    {
      if ((*it)->get_name() == name)
      {
        auto found = std::move(*it);
        tasks.erase(it);
        return found;
      }
    }
    return nullptr;
  }

  struct RecoveryDecisionProtocolFixture
  {
    NetworkState network;
    std::shared_ptr<ccf::kv::test::PrimaryStubConsensus> consensus;
    StubRuntimeControl runtime_control;
    std::unique_ptr<NodeState> node_state;
    ccf::crypto::Pem self_cert;
    ccf::crypto::Pem prev_service_cert;
    ccf::crypto::Pem dummy_enc_pubk;

    RecoveryDecisionProtocolFixture(
      std::vector<sealing_recovery::Location> expected_locations =
        {{"node0", "127.0.0.1:8000"},
         {"node1", "127.0.0.1:8001"},
         {"node2", "127.0.0.1:8002"}},
      std::string retry_timeout = "100ms",
      std::string failover_timeout = "2000ms",
      size_t self_index = 0,
      ::consensus::Index last_recovered_seqno = 5,
      bool drain_board = true)
    {
      if (drain_board)
      {
        drain_main_job_board();
      }

      network.tables->set_encryptor(
        std::make_shared<ccf::kv::NullTxEncryptor>());
      consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
      network.tables->set_consensus(consensus);
      network.identity = make_network_identity();
      network.ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
      network.ledger_secrets->init();
      network.tables->initialise_term(2);

      auto history_kp = ccf::crypto::make_ec_key_pair();
      auto history = std::make_shared<ccf::NullTxHistory>(
        *network.tables, ccf::kv::test::PrimaryNodeId, *history_kp);
      network.tables->set_history(history);

      node_state = std::make_unique<NodeState>(
        nullptr,
        network,
        nullptr,
        ccf::crypto::CurveID::SECP384R1,
        runtime_control,
        nullptr);
      network.tables->set_readiness(ccf::kv::StoreReadiness::Ready);

      auto sign_kp =
        RecoveryDecisionProtocolTestAccess::get_sign_kp(*node_state);
      self_cert = make_self_signed_cert(sign_kp, "CN=SelfNode");
      RecoveryDecisionProtocolTestAccess::set_self_signed_cert(
        *node_state, self_cert);
      RecoveryDecisionProtocolTestAccess::set_consensus(*node_state, consensus);
      RecoveryDecisionProtocolTestAccess::set_last_recovered_signed_idx(
        *node_state, last_recovered_seqno);
      consensus->view_history.update(1, 2);

      CCFConfig cfg;
      SealingRecoveryConfig sr_cfg;
      sr_cfg.location = expected_locations.empty() ?
        sealing_recovery::Location{"node0", "127.0.0.1:8000"} :
        expected_locations.at(self_index);
      RecoveryDecisionProtocolConfig rdp_cfg;
      rdp_cfg.expected_locations = std::move(expected_locations);
      rdp_cfg.message_retry_timeout = {retry_timeout};
      rdp_cfg.failover_timeout = {failover_timeout};
      sr_cfg.recovery_decision_protocol = std::move(rdp_cfg);
      cfg.sealing_recovery = std::move(sr_cfg);
      RecoveryDecisionProtocolTestAccess::set_config(*node_state, cfg);

      prev_service_cert = make_self_signed_cert(
        ccf::crypto::make_ec_key_pair(), "CN=PrevService");
      dummy_enc_pubk = ccf::crypto::make_rsa_key_pair()->public_key_pem();
    }

    ~RecoveryDecisionProtocolFixture()
    {
      // Ensure no periodic tasks outlive the fixture or leak into later tests.
      try
      {
        auto tx = network.tables->create_tx();
        tx.rw<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
          ->put(StateMachine::OPEN);
        (void)tx.commit();
        ccf::tasks::tick(10s);
        for (auto& task : collect_ready_tasks())
        {
          task->cancel_task();
        }
        network.tables->unset_global_hook(
          Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE);
      }
      catch (...)
      {}
    }

    RecoveryDecisionProtocolSubsystem& rdp()
    {
      return node_state->get_recovery_decision_protocol();
    }

    void commit_service_and_self_node(
      ServiceStatus status = ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
    {
      auto tx = network.tables->create_tx();

      ServiceInfo service_info;
      service_info.cert = network.identity->cert;
      service_info.pq_cert = network.identity->pq_cert;
      service_info.status = status;
      service_info.current_service_create_txid = ccf::TxID{2, 1};
      tx.rw<Service>(Tables::SERVICE)->put(service_info);

      tx.rw<PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
        ->put(prev_service_cert);

      ccf::NodeInfo self_node_info;
      self_node_info.cert = self_cert;
      self_node_info.public_key =
        ccf::crypto::public_key_pem_from_cert(self_cert.raw());
      self_node_info.encryption_pub_key = dummy_enc_pubk;
      self_node_info.status = NodeStatus::TRUSTED;
      self_node_info.quote_info.format = QuoteFormat::insecure_virtual;
      tx.rw<Nodes>(Tables::NODES)
        ->put(node_state->get_node_id(), self_node_info);

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      network.tables->compact(tx.commit_version());
    }

    void commit_sm_state(
      StateMachine sm_state,
      StateMachine timeout_state = StateMachine::GOSSIPING)
    {
      auto tx = network.tables->create_tx();
      tx.rw<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
        ->put(sm_state);
      tx.rw<TimeoutSMState>(Tables::RECOVERY_DECISION_PROTOCOL_TIMEOUT_SM_STATE)
        ->put(timeout_state);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      network.tables->compact(tx.commit_version());
    }

    ccf::NodeId add_trusted_node(const ccf::crypto::Pem& cert)
    {
      auto cert_der = ccf::crypto::cert_pem_to_der(cert);
      auto nid = ccf::compute_node_id_from_cert_der(cert_der);
      auto tx = network.tables->create_tx();
      ccf::NodeInfo ni;
      ni.cert = cert;
      ni.public_key = ccf::crypto::public_key_pem_from_cert(cert.raw());
      ni.encryption_pub_key = dummy_enc_pubk;
      ni.status = NodeStatus::TRUSTED;
      tx.rw<Nodes>(Tables::NODES)->put(nid, ni);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      network.tables->compact(tx.commit_version());
      return nid;
    }

    RequestNodeInfo make_request_node_info(
      const std::string& name, const std::string& address = "127.0.0.1:9000")
    {
      RequestNodeInfo info;
      info.quote_info.format = QuoteFormat::insecure_virtual;
      info.location = {name, address};
      info.service_cert_der =
        ccf::crypto::cert_pem_to_der(network.identity->cert);
      return info;
    }

    GossipRequest make_gossip_request(
      const std::string& name, ccf::TxID txid = {2, 5})
    {
      GossipRequest req;
      req.info = make_request_node_info(name);
      req.txid = txid;
      return req;
    }

    TaggedWithNodeInfo make_vote_request(const std::string& name)
    {
      TaggedWithNodeInfo req;
      req.info = make_request_node_info(name);
      return req;
    }

    IAmOpenRequest make_iamopen_request(
      const std::string& name, ccf::TxID txid = {2, 5})
    {
      IAmOpenRequest req;
      req.info = make_request_node_info(name);
      req.prev_service_fingerprint =
        service_fingerprint_from_pem(prev_service_cert);
      req.txid = txid;
      return req;
    }
  };

  TResponse send_node_request(
    RpcFrontend& frontend,
    const std::string& path,
    const nlohmann::json& body,
    const ccf::crypto::Pem& caller_cert,
    llhttp_method method = HTTP_PUT)
  {
    ::http::Request req(path, method);
    req.set_body(body.is_null() ? std::string() : body.dump());
    auto serialised = req.build_request();

    auto caller_der = ccf::crypto::cert_pem_to_der(caller_cert);
    auto session =
      std::make_shared<ccf::SessionContext>(ccf::InvalidSessionId, caller_der);
    auto rpc_ctx = ccf::make_rpc_context(session, serialised);
    frontend.process(rpc_ctx);

    CHECK_FALSE(rpc_ctx->response_is_pending);
    const auto response_bytes = rpc_ctx->serialise_response();

    ::http::SimpleResponseProcessor processor;
    ::http::ResponseParser parser(processor);
    parser.execute(response_bytes.data(), response_bytes.size());
    REQUIRE(processor.received.size() == 1);
    return processor.received.front();
  }

  nlohmann::json parse_error_json(const TResponse& resp)
  {
    return nlohmann::json::parse(resp.body);
  }
}

TEST_CASE("Location equality comparison")
{
  const sealing_recovery::Location a{"node0", "127.0.0.1:8000"};
  const sealing_recovery::Location a_copy{"node0", "127.0.0.1:8000"};
  const sealing_recovery::Location diff_name{"node1", "127.0.0.1:8000"};
  const sealing_recovery::Location diff_addr{"node0", "127.0.0.1:8001"};

  CHECK(a == a_copy);
  CHECK_FALSE(a == diff_name);
  CHECK_FALSE(a == diff_addr);
  CHECK(a != diff_name);
}

TEST_CASE("Handlers reject missing subsystems and missing protocol config")
{
  RecoveryDecisionProtocolFixture fix;
  fix.commit_service_and_self_node();
  const auto caller_kp = ccf::crypto::make_ec_key_pair();
  const auto caller_cert = make_self_signed_cert(caller_kp, "CN=Caller");
  const auto caller_id = fix.add_trusted_node(caller_cert);

  const auto gossip_req = nlohmann::json(fix.make_gossip_request("node1"));
  const auto vote_req = nlohmann::json(fix.make_vote_request("node1"));
  const auto iamopen_req = nlohmann::json(fix.make_iamopen_request("node1"));

  const std::vector<std::pair<std::string, nlohmann::json>> wrapped_calls = {
    {"/recovery_decision_protocol/gossip", gossip_req},
    {"/recovery_decision_protocol/vote", vote_req},
    {"/recovery_decision_protocol/iamopen", iamopen_req}};

  auto make_config_subsystem = [&]() {
    return std::make_shared<NodeConfigurationSubsystem>(
      *fix.node_state, NodeConfigurationSubsystem::InterfaceRegexes{});
  };
  auto make_node_op = [&]() {
    auto op = std::make_shared<ConfigurableNodeOperation>(*fix.node_state);
    op->primary_override = caller_id;
    return op;
  };

  SUBCASE("Missing NodeConfigurationSubsystem")
  {
    TestNodeContext ctx(fix.node_state->get_node_id());
    ctx.install_subsystem(make_node_op());
    NodeRpcFrontend frontend(fix.network, ctx);
    frontend.open();

    for (const auto& [path, body] : wrapped_calls)
    {
      const auto resp = send_node_request(frontend, path, body, caller_cert);
      CHECK(resp.status == HTTP_STATUS_BAD_REQUEST);
      const auto err = parse_error_json(resp)["error"];
      CHECK(err["code"] == ccf::errors::InvalidNodeState);
      CHECK(
        err["message"] ==
        "Unable to open recovery-decision-protocol subsystems");
    }

    const auto timeout_resp = send_node_request(
      frontend, "/recovery_decision_protocol/timeout", nullptr, caller_cert);
    CHECK(timeout_resp.status == HTTP_STATUS_BAD_REQUEST);
    const auto err = parse_error_json(timeout_resp)["error"];
    CHECK(err["code"] == ccf::errors::InvalidNodeState);
    CHECK(
      err["message"] == "Unable to open recovery-decision-protocol subsystems");
  }

  SUBCASE("Missing AbstractNodeOperation")
  {
    TestNodeContext ctx(fix.node_state->get_node_id());
    ctx.install_subsystem(make_config_subsystem());
    RecoveryHandlersFrontend frontend(fix.network, ctx);
    frontend.open();

    for (const auto& [path, body] : wrapped_calls)
    {
      const auto resp = send_node_request(frontend, path, body, caller_cert);
      CHECK(resp.status == HTTP_STATUS_BAD_REQUEST);
      const auto err = parse_error_json(resp)["error"];
      CHECK(err["code"] == ccf::errors::InvalidNodeState);
      CHECK(
        err["message"] ==
        "Unable to open recovery-decision-protocol subsystems");
    }

    const auto timeout_resp = send_node_request(
      frontend, "/recovery_decision_protocol/timeout", nullptr, caller_cert);
    CHECK(timeout_resp.status == HTTP_STATUS_BAD_REQUEST);
    const auto err = parse_error_json(timeout_resp)["error"];
    CHECK(err["code"] == ccf::errors::InvalidNodeState);
    CHECK(
      err["message"] == "Unable to open recovery-decision-protocol subsystems");
  }

  SUBCASE("Missing sealing_recovery configuration")
  {
    RecoveryDecisionProtocolTestAccess::clear_sealing_recovery(*fix.node_state);
    TestNodeContext ctx(fix.node_state->get_node_id());
    ctx.install_subsystem(make_config_subsystem());
    ctx.install_subsystem(make_node_op());
    NodeRpcFrontend frontend(fix.network, ctx);
    frontend.open();

    for (const auto& [path, body] : wrapped_calls)
    {
      const auto resp = send_node_request(frontend, path, body, caller_cert);
      CHECK(resp.status == HTTP_STATUS_BAD_REQUEST);
      const auto err = parse_error_json(resp)["error"];
      CHECK(err["code"] == ccf::errors::InvalidNodeState);
      CHECK(err["message"] == "This node cannot do recovery-decision-protocol");
    }

    const auto timeout_resp = send_node_request(
      frontend, "/recovery_decision_protocol/timeout", nullptr, caller_cert);
    CHECK(timeout_resp.status == HTTP_STATUS_BAD_REQUEST);
    const auto err = parse_error_json(timeout_resp)["error"];
    CHECK(err["code"] == ccf::errors::InvalidNodeState);
    CHECK(err["message"] == "This node cannot do recovery-decision-protocol");
  }

  SUBCASE("Missing recovery_decision_protocol configuration")
  {
    RecoveryDecisionProtocolTestAccess::clear_rdp_config(*fix.node_state);
    TestNodeContext ctx(fix.node_state->get_node_id());
    ctx.install_subsystem(make_config_subsystem());
    ctx.install_subsystem(make_node_op());
    NodeRpcFrontend frontend(fix.network, ctx);
    frontend.open();

    for (const auto& [path, body] : wrapped_calls)
    {
      const auto resp = send_node_request(frontend, path, body, caller_cert);
      CHECK(resp.status == HTTP_STATUS_BAD_REQUEST);
      const auto err = parse_error_json(resp)["error"];
      CHECK(err["code"] == ccf::errors::InvalidNodeState);
      CHECK(err["message"] == "This node cannot do recovery-decision-protocol");
    }

    const auto timeout_resp = send_node_request(
      frontend, "/recovery_decision_protocol/timeout", nullptr, caller_cert);
    CHECK(timeout_resp.status == HTTP_STATUS_BAD_REQUEST);
    const auto err = parse_error_json(timeout_resp)["error"];
    CHECK(err["code"] == ccf::errors::InvalidNodeState);
    CHECK(err["message"] == "This node cannot do recovery-decision-protocol");
  }
}

TEST_CASE("Handlers reject invalid quotes and changed sender certificates")
{
  RecoveryDecisionProtocolFixture fix;
  fix.commit_service_and_self_node();
  fix.commit_sm_state(StateMachine::GOSSIPING, StateMachine::GOSSIPING);

  TestNodeContext ctx(fix.node_state->get_node_id());
  ctx.install_subsystem(std::make_shared<NodeConfigurationSubsystem>(
    *fix.node_state, NodeConfigurationSubsystem::InterfaceRegexes{}));
  auto node_op = std::make_shared<ConfigurableNodeOperation>(*fix.node_state);
  ctx.install_subsystem(node_op);
  NodeRpcFrontend frontend(fix.network, ctx);
  frontend.open();

  const auto peer_kp_a = ccf::crypto::make_ec_key_pair();
  const auto peer_cert_a = make_self_signed_cert(peer_kp_a, "CN=PeerA");
  const auto peer_kp_b = ccf::crypto::make_ec_key_pair();
  const auto peer_cert_b = make_self_signed_cert(peer_kp_b, "CN=PeerB");

  const std::vector<std::pair<std::string, nlohmann::json>> wrapped_calls = {
    {"/recovery_decision_protocol/gossip",
     nlohmann::json(fix.make_gossip_request("node1"))},
    {"/recovery_decision_protocol/vote",
     nlohmann::json(fix.make_vote_request("node1"))},
    {"/recovery_decision_protocol/iamopen",
     nlohmann::json(fix.make_iamopen_request("node1"))}};

  INFO("Invalid quote is rejected before recording sender identity");
  node_op->verify_quote_override =
    QuoteVerificationResult::FailedInvalidQuotedPublicKey;
  for (const auto& [path, body] : wrapped_calls)
  {
    const auto resp = send_node_request(frontend, path, body, peer_cert_a);
    CHECK(resp.status == HTTP_STATUS_UNAUTHORIZED);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["code"] == ccf::errors::InvalidQuote);
  }
  {
    auto ro = fix.network.tables->create_read_only_tx();
    CHECK_FALSE(ro.ro<NodeInfoMap>(Tables::RECOVERY_DECISION_PROTOCOL_NODES)
                  ->get("node1")
                  .has_value());
  }

  INFO("First valid message binds location name to caller public key");
  node_op->verify_quote_override = QuoteVerificationResult::Verified;
  {
    const auto resp = send_node_request(
      frontend,
      "/recovery_decision_protocol/gossip",
      nlohmann::json(fix.make_gossip_request("node1", {2, 10})),
      peer_cert_a);
    CHECK(resp.status == HTTP_STATUS_NO_CONTENT);
  }

  INFO("Same location with the same certificate key is accepted");
  {
    const auto resp = send_node_request(
      frontend,
      "/recovery_decision_protocol/gossip",
      nlohmann::json(fix.make_gossip_request("node1", {2, 10})),
      peer_cert_a);
    CHECK(resp.status == HTTP_STATUS_NO_CONTENT);
  }

  INFO("Same location with a different certificate key is rejected");
  for (const auto& [path, body] : wrapped_calls)
  {
    const auto resp = send_node_request(frontend, path, body, peer_cert_b);
    CHECK(resp.status == HTTP_STATUS_BAD_REQUEST);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["code"] == ccf::errors::NodeAlreadyExists);
    CHECK(err["message"].get<std::string>().contains(
      "certificate public key has changed"));
  }
}

TEST_CASE("Timeout handler enforces primary origin and catches logic_error")
{
  RecoveryDecisionProtocolFixture fix;
  fix.commit_service_and_self_node();

  const auto primary_kp = ccf::crypto::make_ec_key_pair();
  const auto primary_cert = make_self_signed_cert(primary_kp, "CN=Primary");
  const auto primary_id = fix.add_trusted_node(primary_cert);

  const auto backup_kp = ccf::crypto::make_ec_key_pair();
  const auto backup_cert = make_self_signed_cert(backup_kp, "CN=Backup");
  const auto backup_id = fix.add_trusted_node(backup_cert);

  TestNodeContext ctx(fix.node_state->get_node_id());
  ctx.install_subsystem(std::make_shared<NodeConfigurationSubsystem>(
    *fix.node_state, NodeConfigurationSubsystem::InterfaceRegexes{}));
  auto node_op = std::make_shared<ConfigurableNodeOperation>(*fix.node_state);
  ctx.install_subsystem(node_op);
  NodeRpcFrontend frontend(fix.network, ctx);
  frontend.open();

  INFO("Unknown primary is rejected with 500 InternalError");
  node_op->primary_override = std::optional<ccf::NodeId>(std::nullopt);
  {
    const auto resp = send_node_request(
      frontend, "/recovery_decision_protocol/timeout", nullptr, primary_cert);
    CHECK(resp.status == HTTP_STATUS_INTERNAL_SERVER_ERROR);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["code"] == ccf::errors::InternalError);
    CHECK(err["message"] == "Primary is unknown");
  }

  INFO("Non-primary caller is rejected with 500 InternalError");
  node_op->primary_override = std::optional<ccf::NodeId>(primary_id);
  {
    const auto resp = send_node_request(
      frontend, "/recovery_decision_protocol/timeout", nullptr, backup_cert);
    CHECK(resp.status == HTTP_STATUS_INTERNAL_SERVER_ERROR);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["code"] == ccf::errors::InternalError);
    CHECK(err["message"] == "Request does not originate from primary.");
  }

  INFO("std::logic_error from advance() is caught and mapped to 500");
  // SMState is not set, so advance() throws std::logic_error.
  {
    const auto resp = send_node_request(
      frontend, "/recovery_decision_protocol/timeout", nullptr, primary_cert);
    CHECK(resp.status == HTTP_STATUS_INTERNAL_SERVER_ERROR);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["code"] == ccf::errors::InternalError);
    CHECK(err["message"].get<std::string>().contains(
      "Failed to advance recovery-decision-protocol state:"));
  }

  INFO("Primary caller advances protocol on valid timeout");
  fix.commit_sm_state(StateMachine::OPENING, StateMachine::OPENING);
  {
    const auto resp = send_node_request(
      frontend, "/recovery_decision_protocol/timeout", nullptr, primary_cert);
    CHECK(resp.status == HTTP_STATUS_OK);
    auto ro = fix.network.tables->create_read_only_tx();
    CHECK(
      ro.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)->get() ==
      StateMachine::OPEN);
  }
}

TEST_CASE(
  "Wrapped handlers catch advance() logic_error and unset iamopen state")
{
  RecoveryDecisionProtocolFixture fix;
  fix.commit_service_and_self_node();

  TestNodeContext ctx(fix.node_state->get_node_id());
  ctx.install_subsystem(std::make_shared<NodeConfigurationSubsystem>(
    *fix.node_state, NodeConfigurationSubsystem::InterfaceRegexes{}));
  auto node_op = std::make_shared<ConfigurableNodeOperation>(*fix.node_state);
  ctx.install_subsystem(node_op);
  NodeRpcFrontend frontend(fix.network, ctx);
  frontend.open();

  const auto peer_kp = ccf::crypto::make_ec_key_pair();
  const auto peer_cert = make_self_signed_cert(peer_kp, "CN=Peer");

  INFO(
    "gossip and vote catch std::logic_error from advance() when SMState unset");
  for (const auto& [path, body] :
       std::vector<std::pair<std::string, nlohmann::json>>{
         {"/recovery_decision_protocol/gossip",
          nlohmann::json(fix.make_gossip_request("node1"))},
         {"/recovery_decision_protocol/vote",
          nlohmann::json(fix.make_vote_request("node1"))}})
  {
    const auto resp = send_node_request(frontend, path, body, peer_cert);
    CHECK(resp.status == HTTP_STATUS_INTERNAL_SERVER_ERROR);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["code"] == ccf::errors::InternalError);
    CHECK(err["message"].get<std::string>().contains(
      "Failed to advance recovery-decision-protocol state:"));
  }

  INFO("iamopen throws std::logic_error when SMState is not set");
  {
    const auto resp = send_node_request(
      frontend,
      "/recovery_decision_protocol/iamopen",
      nlohmann::json(fix.make_iamopen_request("node1")),
      peer_cert);
    CHECK(resp.status == HTTP_STATUS_INTERNAL_SERVER_ERROR);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["code"] == ccf::errors::InternalError);
  }

  INFO(
    "iamopen catches std::logic_error from advance() when TimeoutSMState "
    "unset");
  {
    auto tx = fix.network.tables->create_tx();
    tx.rw<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
      ->put(StateMachine::VOTING);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto resp = send_node_request(
      frontend,
      "/recovery_decision_protocol/iamopen",
      nlohmann::json(fix.make_iamopen_request("node1")),
      peer_cert);
    CHECK(resp.status == HTTP_STATUS_INTERNAL_SERVER_ERROR);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["code"] == ccf::errors::InternalError);
    CHECK(err["message"].get<std::string>().contains(
      "Failed to advance recovery-decision-protocol state:"));
  }

  INFO("iamopen rejects requests once the node is already OPENING or OPEN");
  for (const auto state : {StateMachine::OPENING, StateMachine::OPEN})
  {
    fix.commit_sm_state(state, StateMachine::OPENING);
    const auto resp = send_node_request(
      frontend,
      "/recovery_decision_protocol/iamopen",
      nlohmann::json(fix.make_iamopen_request("node1")),
      peer_cert);
    CHECK(resp.status == HTTP_STATUS_BAD_REQUEST);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["code"] == ccf::errors::InvalidNodeState);
  }

  INFO("iamopen transitions to JOINING and requests restart when not yet open");
  {
    fix.commit_sm_state(StateMachine::VOTING, StateMachine::VOTING);
    const auto before_restarts = fix.runtime_control.restart_count;
    const auto resp = send_node_request(
      frontend,
      "/recovery_decision_protocol/iamopen",
      nlohmann::json(fix.make_iamopen_request("node1")),
      peer_cert);
    CHECK(resp.status == HTTP_STATUS_NO_CONTENT);
    CHECK(fix.runtime_control.restart_count == before_restarts + 1);
    auto ro = fix.network.tables->create_read_only_tx();
    CHECK(
      ro.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)->get() ==
      StateMachine::JOINING);
    CHECK(
      ro.ro<ChosenNode>(Tables::RECOVERY_DECISION_PROTOCOL_CHOSEN_NODE)
        ->get() == "node1");
  }

  INFO("gossip is rejected once chosen node is already set");
  {
    const auto resp = send_node_request(
      frontend,
      "/recovery_decision_protocol/gossip",
      nlohmann::json(fix.make_gossip_request("node2")),
      peer_cert);
    CHECK(resp.status == HTTP_STATUS_INTERNAL_SERVER_ERROR);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["message"].get<std::string>().contains(
      "This node has already voted for node1"));
  }
}

TEST_CASE(
  "Protocol advance() covers voting safety, open, and timeout transitions")
{
  RecoveryDecisionProtocolFixture fix;
  fix.commit_service_and_self_node();

  SUBCASE("GOSSIPING timeout with empty gossips throws std::logic_error")
  {
    fix.commit_sm_state(StateMachine::GOSSIPING, StateMachine::GOSSIPING);
    auto tx = fix.network.tables->create_tx();
    AdvanceTrace trace;
    REQUIRE_THROWS_WITH_AS(
      fix.rdp().advance(tx, true, trace),
      "No gossip addresses provided yet",
      std::logic_error);
  }

  SUBCASE("GOSSIPING selects lexicographical max <view, seqno, name>")
  {
    fix.commit_sm_state(StateMachine::GOSSIPING, StateMachine::GOSSIPING);
    auto tx = fix.network.tables->create_tx();
    auto* gossips = tx.rw<Gossips>(Tables::RECOVERY_DECISION_PROTOCOL_GOSSIPS);
    gossips->put("node0", ccf::TxID{2, 10});
    gossips->put("node1", ccf::TxID{3, 5});
    gossips->put("node2", ccf::TxID{3, 5});

    AdvanceTrace trace;
    fix.rdp().advance(tx, false, trace);
    CHECK(trace.pre == StateMachine::GOSSIPING);
    CHECK(trace.post == StateMachine::VOTING);
    CHECK(trace.chosen == "node2");
    CHECK(
      tx.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)->get() ==
      StateMachine::VOTING);
  }

  SUBCASE("VOTING timeout with zero votes refuses to failover-open")
  {
    fix.commit_sm_state(StateMachine::VOTING, StateMachine::VOTING);
    auto tx = fix.network.tables->create_tx();
    AdvanceTrace trace;
    fix.rdp().advance(tx, true, trace);

    CHECK(trace.pre == StateMachine::VOTING);
    CHECK(trace.post == StateMachine::VOTING);
    CHECK(trace.pre_timeout == StateMachine::VOTING);
    CHECK(trace.post_timeout == StateMachine::VOTING);
    CHECK_FALSE(trace.open_kind.has_value());
    CHECK(
      tx.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)->get() ==
      StateMachine::VOTING);
    CHECK(
      tx.ro<TimeoutSMState>(Tables::RECOVERY_DECISION_PROTOCOL_TIMEOUT_SM_STATE)
        ->get() == StateMachine::VOTING);
    CHECK_FALSE(tx.ro<OpenKind>(Tables::RECOVERY_DECISION_PROTOCOL_OPEN_KIND)
                  ->get()
                  .has_value());
  }

  SUBCASE("VOTING timeout with quorum still records QUORUM open kind")
  {
    fix.commit_sm_state(StateMachine::VOTING, StateMachine::VOTING);
    auto tx = fix.network.tables->create_tx();
    auto* votes = tx.rw<Votes>(Tables::RECOVERY_DECISION_PROTOCOL_VOTES);
    votes->insert("node0");
    votes->insert("node1");

    AdvanceTrace trace;
    fix.rdp().advance(tx, true, trace);

    CHECK(trace.post == StateMachine::OPENING);
    CHECK(trace.post_timeout == StateMachine::OPENING);
    CHECK(trace.open_kind == OpenKinds::QUORUM);
    CHECK(
      tx.ro<OpenKind>(Tables::RECOVERY_DECISION_PROTOCOL_OPEN_KIND)->get() ==
      OpenKinds::QUORUM);
  }

  SUBCASE("VOTING timeout with single non-quorum vote opens via FAILOVER")
  {
    fix.commit_sm_state(StateMachine::VOTING, StateMachine::VOTING);
    auto tx = fix.network.tables->create_tx();
    tx.rw<Votes>(Tables::RECOVERY_DECISION_PROTOCOL_VOTES)->insert("node0");

    AdvanceTrace trace;
    fix.rdp().advance(tx, true, trace);

    CHECK(trace.post == StateMachine::OPENING);
    CHECK(trace.open_kind == OpenKinds::FAILOVER);
    CHECK(
      tx.ro<OpenKind>(Tables::RECOVERY_DECISION_PROTOCOL_OPEN_KIND)->get() ==
      OpenKinds::FAILOVER);
  }

  SUBCASE("OPENING -> OPEN on timeout and OPEN is an idempotent no-op")
  {
    fix.commit_sm_state(StateMachine::OPENING, StateMachine::OPENING);
    {
      auto tx = fix.network.tables->create_tx();
      AdvanceTrace trace;
      fix.rdp().advance(tx, true, trace);
      CHECK(trace.pre == StateMachine::OPENING);
      CHECK(trace.post == StateMachine::OPEN);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
    for (const bool is_timeout : {false, true})
    {
      auto tx = fix.network.tables->create_tx();
      AdvanceTrace trace;
      fix.rdp().advance(tx, is_timeout, trace);
      CHECK(trace.pre == StateMachine::OPEN);
      CHECK(trace.post == StateMachine::OPEN);
    }
  }

  SUBCASE(
    "Timeout state machine handles GOSSIPING, VOTING, OPENING, JOINING, OPEN")
  {
    for (const auto [initial_timeout, expected_timeout] :
         std::vector<std::pair<StateMachine, StateMachine>>{
           {StateMachine::GOSSIPING, StateMachine::VOTING},
           {StateMachine::VOTING, StateMachine::OPENING},
           {StateMachine::OPENING, StateMachine::OPENING},
           {StateMachine::JOINING, StateMachine::JOINING},
           {StateMachine::OPEN, StateMachine::OPEN}})
    {
      fix.commit_sm_state(StateMachine::OPEN, initial_timeout);
      auto tx = fix.network.tables->create_tx();
      AdvanceTrace trace;
      fix.rdp().advance(tx, true, trace);
      CHECK(trace.pre_timeout == initial_timeout);
      CHECK(trace.post_timeout == expected_timeout);
      CHECK(
        tx.ro<TimeoutSMState>(
            Tables::RECOVERY_DECISION_PROTOCOL_TIMEOUT_SM_STATE)
          ->get() == expected_timeout);
    }
  }
}

TEST_CASE("Protocol advance() defensive guards throw std::logic_error")
{
  RecoveryDecisionProtocolFixture fix;
  fix.commit_service_and_self_node();

  SUBCASE("Missing sealing_recovery config")
  {
    RecoveryDecisionProtocolTestAccess::clear_sealing_recovery(*fix.node_state);
    auto tx = fix.network.tables->create_tx();
    AdvanceTrace trace;
    REQUIRE_THROWS_WITH_AS(
      fix.rdp().advance(tx, false, trace),
      "Sealing recovery not configured",
      std::logic_error);
  }

  SUBCASE("Missing recovery_decision_protocol config")
  {
    RecoveryDecisionProtocolTestAccess::clear_rdp_config(*fix.node_state);
    auto tx = fix.network.tables->create_tx();
    AdvanceTrace trace;
    REQUIRE_THROWS_WITH_AS(
      fix.rdp().advance(tx, false, trace),
      "Recovery-decision-protocol not configured",
      std::logic_error);
  }

  SUBCASE("Missing SMState")
  {
    auto tx = fix.network.tables->create_tx();
    tx.rw<TimeoutSMState>(Tables::RECOVERY_DECISION_PROTOCOL_TIMEOUT_SM_STATE)
      ->put(StateMachine::GOSSIPING);
    AdvanceTrace trace;
    REQUIRE_THROWS_WITH_AS(
      fix.rdp().advance(tx, false, trace),
      "Recovery-decision-protocol state not set, cannot advance protocol",
      std::logic_error);
  }

  SUBCASE("Missing TimeoutSMState")
  {
    auto tx = fix.network.tables->create_tx();
    tx.rw<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
      ->put(StateMachine::GOSSIPING);
    AdvanceTrace trace;
    REQUIRE_THROWS_WITH_AS(
      fix.rdp().advance(tx, false, trace),
      "Recovery-decision-protocol state not set, cannot advance protocol",
      std::logic_error);
  }

  SUBCASE("Missing Tables::SERVICE when opening")
  {
    fix.commit_sm_state(StateMachine::VOTING, StateMachine::VOTING);
    auto tx = fix.network.tables->create_tx();
    tx.rw<Service>(Tables::SERVICE)->clear();
    auto* votes = tx.rw<Votes>(Tables::RECOVERY_DECISION_PROTOCOL_VOTES);
    votes->insert("node0");
    votes->insert("node1");
    AdvanceTrace trace;
    REQUIRE_THROWS_WITH_AS(
      fix.rdp().advance(tx, false, trace),
      "Service information cannot be found to transition service to open",
      std::logic_error);
  }

  SUBCASE("JOINING without ChosenNode")
  {
    fix.commit_sm_state(StateMachine::JOINING, StateMachine::GOSSIPING);
    auto tx = fix.network.tables->create_tx();
    AdvanceTrace trace;
    REQUIRE_THROWS_WITH_AS(
      fix.rdp().advance(tx, false, trace),
      "Recovery-decision-protocol chosen node not set, cannot join",
      std::logic_error);
  }

  SUBCASE("JOINING with ChosenNode absent from NodeInfoMap")
  {
    fix.commit_sm_state(StateMachine::JOINING, StateMachine::GOSSIPING);
    auto tx = fix.network.tables->create_tx();
    tx.rw<ChosenNode>(Tables::RECOVERY_DECISION_PROTOCOL_CHOSEN_NODE)
      ->put("missing-peer");
    AdvanceTrace trace;
    REQUIRE_THROWS_WITH_AS(
      fix.rdp().advance(tx, false, trace),
      "Recovery-decision-protocol chosen node missing-peer not found",
      std::logic_error);
  }
}

TEST_CASE("try_start global hook, retry_task, failover_task, and stop_timers")
{
  SUBCASE("try_start skips when unconfigured or not recovering")
  {
    RecoveryDecisionProtocolFixture fix;
    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().try_start(tx, false);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      auto ro = fix.network.tables->create_read_only_tx();
      CHECK_FALSE(ro.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
                    ->get()
                    .has_value());
    }
    RecoveryDecisionProtocolTestAccess::clear_rdp_config(*fix.node_state);
    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().try_start(tx, true);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      auto ro = fix.network.tables->create_read_only_tx();
      CHECK_FALSE(ro.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
                    ->get()
                    .has_value());
    }
    RecoveryDecisionProtocolTestAccess::clear_sealing_recovery(*fix.node_state);
    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().try_start(tx, true);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      auto ro = fix.network.tables->create_read_only_tx();
      CHECK_FALSE(ro.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
                    ->get()
                    .has_value());
    }
  }

  SUBCASE("JOINING in retry_task stops both retry and failover timers")
  {
    RecoveryDecisionProtocolFixture fix(
      {{"node0", "127.0.0.1:8000"},
       {"node1", "127.0.0.1:8001"},
       {"node2", "127.0.0.1:8002"}},
      "50ms",
      "500ms");
    fix.commit_service_and_self_node();

    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().try_start(tx, true);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      fix.network.tables->compact(tx.commit_version());
    }

    // Committing a non-GOSSIPING write exercises the hook false branch on
    // value.
    fix.commit_sm_state(StateMachine::JOINING, StateMachine::GOSSIPING);

    ccf::tasks::tick(100ms);
    auto tasks = collect_ready_tasks();
    auto retry_task = take_named_task(tasks, "RecoveryDecisionProtocolRetry");
    REQUIRE(retry_task != nullptr);
    retry_task->do_task();
    CHECK(retry_task->is_cancelled());

    // Failover timer should also have been cancelled by stop_timers().
    ccf::tasks::tick(1000ms);
    for (auto& task : collect_ready_tasks())
    {
      CHECK(task->is_cancelled());
    }

    // Clearing SMState via reset_state exercises the hook false branch on empty
    // write.
    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().reset_state(tx);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      fix.network.tables->compact(tx.commit_version());
    }
  }

  SUBCASE("stop_timers handles null failover_task when failover_timeout is 0ms")
  {
    RecoveryDecisionProtocolFixture fix(
      {{"node0", "127.0.0.1:8000"}, {"node1", "127.0.0.1:8001"}},
      "50ms",
      "0ms");
    fix.commit_service_and_self_node();

    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().try_start(tx, true);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      fix.network.tables->compact(tx.commit_version());
    }

    fix.commit_sm_state(StateMachine::OPEN, StateMachine::OPENING);

    ccf::tasks::tick(100ms);
    auto tasks = collect_ready_tasks();
    auto retry_task = take_named_task(tasks, "RecoveryDecisionProtocolRetry");
    REQUIRE(retry_task != nullptr);
    retry_task->do_task();
    CHECK(retry_task->is_cancelled());
  }

  SUBCASE(
    "retry_task defensive guards on missing config, state, and voting metadata")
  {
    RecoveryDecisionProtocolFixture fix(
      {{"node0", "127.0.0.1:8000"}, {"node1", "127.0.0.1:8001"}},
      "50ms",
      "500ms");
    fix.commit_service_and_self_node();

    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().try_start(tx, true);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      fix.network.tables->compact(tx.commit_version());
    }

    ccf::tasks::tick(100ms);
    auto tasks = collect_ready_tasks();
    auto retry_task = take_named_task(tasks, "RecoveryDecisionProtocolRetry");
    REQUIRE(retry_task != nullptr);

    INFO("VOTING with missing ChosenNode throws std::logic_error");
    fix.commit_sm_state(StateMachine::VOTING, StateMachine::GOSSIPING);
    REQUIRE_THROWS_WITH_AS(
      retry_task->do_task(),
      "Recovery-decision-protocol chosen node not set, cannot vote",
      std::logic_error);

    INFO(
      "VOTING with ChosenNode absent from NodeInfoMap throws std::logic_error");
    {
      auto tx = fix.network.tables->create_tx();
      tx.rw<ChosenNode>(Tables::RECOVERY_DECISION_PROTOCOL_CHOSEN_NODE)
        ->put("ghost");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
    REQUIRE_THROWS_WITH_AS(
      retry_task->do_task(),
      "Recovery-decision-protocol chosen node ghost not found",
      std::logic_error);

    INFO("Missing SMState throws std::logic_error");
    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().reset_state(tx);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
    REQUIRE_THROWS_WITH_AS(
      retry_task->do_task(),
      "Recovery-decision-protocol state not set, cannot retry protocol",
      std::logic_error);

    INFO("Missing recovery_decision_protocol config throws std::logic_error");
    RecoveryDecisionProtocolTestAccess::clear_rdp_config(*fix.node_state);
    REQUIRE_THROWS_WITH_AS(
      retry_task->do_task(),
      "Recovery-decision-protocol not configured",
      std::logic_error);

    INFO("Missing sealing_recovery config skips retry cleanly");
    RecoveryDecisionProtocolTestAccess::clear_sealing_recovery(*fix.node_state);
    CHECK_NOTHROW(retry_task->do_task());

    retry_task->cancel_task();
  }

  SUBCASE(
    "failover_task handles missing config, missing state, active send, and "
    "OPEN")
  {
    RecoveryDecisionProtocolFixture fix(
      {{"node0", "127.0.0.1:1"}, {"node1", "127.0.0.1:1"}}, "500ms", "50ms");
    fix.commit_service_and_self_node();

    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().try_start(tx, true);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      fix.network.tables->compact(tx.commit_version());
    }

    ccf::tasks::tick(100ms);
    auto tasks = collect_ready_tasks();
    auto failover_task =
      take_named_task(tasks, "RecoveryDecisionProtocolFailover");
    REQUIRE(failover_task != nullptr);

    INFO("Active GOSSIPING state dispatches timeout request via curl");
    {
      ccf::http_client::CurlmLibuvContextSingleton singleton(uv_default_loop());
      CHECK_NOTHROW(failover_task->do_task());
    }
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    INFO("Missing SMState throws std::logic_error");
    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().reset_state(tx);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
    REQUIRE_THROWS_WITH_AS(
      failover_task->do_task(),
      "Recovery-decision-protocol state not set, cannot retry protocol",
      std::logic_error);

    INFO("OPEN stops failover and retry timers");
    fix.commit_sm_state(StateMachine::OPEN, StateMachine::OPENING);
    failover_task->do_task();
    CHECK(failover_task->is_cancelled());
  }
}

TEST_CASE("get_iamopen_request and metadata helpers report missing state")
{
  SUBCASE("Missing PREVIOUS_SERVICE_IDENTITY throws std::logic_error")
  {
    RecoveryDecisionProtocolFixture fix;
    auto tx = fix.network.tables->create_read_only_tx();
    REQUIRE_THROWS_WITH_AS(
      static_cast<void>(fix.rdp().get_iamopen_request(tx)),
      "Previous service identity not found in table but expected as recovering",
      std::logic_error);
  }

  SUBCASE("Missing self entry in Tables::NODES throws std::logic_error")
  {
    RecoveryDecisionProtocolFixture fix;
    {
      auto tx = fix.network.tables->create_tx();
      tx.rw<PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
        ->put(fix.prev_service_cert);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
    auto ro = fix.network.tables->create_read_only_tx();
    REQUIRE_THROWS_AS(
      static_cast<void>(fix.rdp().get_iamopen_request(ro)), std::logic_error);
  }

  SUBCASE("Missing sealing_recovery in get_location() throws std::logic_error")
  {
    RecoveryDecisionProtocolFixture fix;
    fix.commit_service_and_self_node();
    RecoveryDecisionProtocolTestAccess::clear_sealing_recovery(*fix.node_state);
    auto ro = fix.network.tables->create_read_only_tx();
    REQUIRE_THROWS_WITH_AS(
      static_cast<void>(fix.rdp().get_iamopen_request(ro)),
      "Sealing recovery not configured",
      std::logic_error);
  }

  SUBCASE("Unknown view for last_recovered_signed_idx throws std::logic_error")
  {
    RecoveryDecisionProtocolFixture fix;
    fix.commit_service_and_self_node();
    // View history has no entry for seqno 0, so get_view(0) returns
    // VIEW_UNKNOWN.
    RecoveryDecisionProtocolTestAccess::set_last_recovered_signed_idx(
      *fix.node_state, 0);
    auto ro = fix.network.tables->create_read_only_tx();
    REQUIRE_THROWS_WITH_AS(
      static_cast<void>(fix.rdp().get_iamopen_request(ro)),
      "Could not find view for last recovered signed seqno 0",
      std::logic_error);
  }

  SUBCASE("Valid state constructs and caches IAmOpenRequest")
  {
    RecoveryDecisionProtocolFixture fix;
    fix.commit_service_and_self_node();
    auto ro = fix.network.tables->create_read_only_tx();
    const auto& first = fix.rdp().get_iamopen_request(ro);
    CHECK(first.info.location.name == "node0");
    CHECK(first.txid == ccf::TxID{2, 5});
    const auto& second = fix.rdp().get_iamopen_request(ro);
    CHECK(&first == &second);
  }
}

namespace
{
  class RdpTraceCaptureLogger : public ccf::logger::AbstractLogger
  {
  public:
    std::map<std::string, std::vector<std::string>> lines_by_node;
    std::vector<std::string> trace_failures;

    void write(const ccf::logger::LogLine& ll) override
    {
      if (ll.msg.contains("Failed to trace recovery-decision-protocol"))
      {
        trace_failures.push_back(ll.msg);
      }
      constexpr std::string_view marker = "RDP_TRACE ";
      const auto pos = ll.msg.find(marker);
      if (pos == std::string::npos)
      {
        return;
      }
      const auto payload = ll.msg.substr(pos + marker.size());
      const auto parsed = nlohmann::json::parse(payload);
      const auto node = parsed.at("node").get<std::string>();
      lines_by_node[node].push_back(ll.msg.substr(pos));
    }
  };

  struct ScopedRdpTraceCapture
  {
    std::string scenario_name;
    size_t participants;
    RdpTraceCaptureLogger* logger = nullptr;

    ScopedRdpTraceCapture(std::string scenario_name_, size_t participants_) :
      scenario_name(std::move(scenario_name_)),
      participants(participants_)
    {
      auto capture = std::make_unique<RdpTraceCaptureLogger>();
      logger = capture.get();
      ccf::logger::config::loggers().push_back(std::move(capture));
    }

    ~ScopedRdpTraceCapture()
    {
      if (logger != nullptr)
      {
        CHECK(logger->trace_failures.empty());
        try
        {
          // NOLINTNEXTLINE(concurrency-mt-unsafe)
          const char* out_dir = std::getenv("CCF_RDP_TRACE_OUTPUT_DIR");
          if (out_dir != nullptr && !std::string_view(out_dir).empty())
          {
            const auto scenario_dir =
              std::filesystem::path(out_dir) / scenario_name;
            std::filesystem::create_directories(scenario_dir);
            {
              std::ofstream meta(scenario_dir / "scenario.json");
              meta << nlohmann::json{{"participants", participants}}.dump(2)
                   << "\n";
            }
            for (const auto& [node, lines] : logger->lines_by_node)
            {
              std::ofstream out(scenario_dir / (node + ".out"));
              for (const auto& line : lines)
              {
                out << line << "\n";
              }
            }
          }
        }
        catch (...)
        {}

        auto& loggers = ccf::logger::config::loggers();
        loggers.erase(
          std::remove_if(
            loggers.begin(),
            loggers.end(),
            [this](const auto& ptr) { return ptr.get() == logger; }),
          loggers.end());
      }
    }
  };

  struct VirtualRecoveryNode
  {
    sealing_recovery::Location location;
    ccf::TxID recovered_txid;
    RecoveryDecisionProtocolFixture fix;
    TestNodeContext ctx;
    std::shared_ptr<ConfigurableNodeOperation> node_op;
    std::unique_ptr<NodeRpcFrontend> frontend;
    ccf::tasks::Task retry_task;
    ccf::tasks::Task failover_task;

    VirtualRecoveryNode(
      const std::vector<sealing_recovery::Location>& expected_locations,
      size_t self_index,
      ccf::TxID recovered_txid_,
      const ccf::crypto::Pem& shared_prev_service_cert,
      std::string failover_timeout = "60000ms") :
      location(expected_locations.at(self_index)),
      recovered_txid(recovered_txid_),
      fix(
        expected_locations,
        "60000ms",
        std::move(failover_timeout),
        self_index,
        recovered_txid_.seqno,
        false),
      ctx(fix.node_state->get_node_id()),
      node_op(std::make_shared<ConfigurableNodeOperation>(*fix.node_state))
    {
      fix.prev_service_cert = shared_prev_service_cert;
      fix.consensus->view_history.update(1, recovered_txid.view);
      fix.commit_service_and_self_node();
      node_op->primary_override = fix.node_state->get_node_id();
      ctx.install_subsystem(std::make_shared<NodeConfigurationSubsystem>(
        *fix.node_state, NodeConfigurationSubsystem::InterfaceRegexes{}));
      ctx.install_subsystem(node_op);
      frontend = std::make_unique<NodeRpcFrontend>(fix.network, ctx);
      frontend->set_consensus_and_history(fix.consensus.get(), nullptr);
      frontend->open();
    }

    ~VirtualRecoveryNode()
    {
      if (retry_task != nullptr)
      {
        retry_task->cancel_task();
      }
      if (failover_task != nullptr)
      {
        failover_task->cancel_task();
      }
    }

    void start()
    {
      auto tx = fix.network.tables->create_tx();
      fix.rdp().reset_state(tx);
      fix.rdp().try_start(tx, true);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      fix.network.tables->compact(tx.commit_version());

      ccf::tasks::tick(1ms);
      auto ready = collect_ready_tasks();
      retry_task = take_named_task(ready, "RecoveryDecisionProtocolRetry");
      REQUIRE(retry_task != nullptr);
    }

    void run_failover_task(std::chrono::milliseconds tick_ms = 30000ms)
    {
      if (failover_task == nullptr)
      {
        ccf::tasks::tick(tick_ms);
        auto ready = collect_ready_tasks();
        failover_task =
          take_named_task(ready, "RecoveryDecisionProtocolFailover");
      }
      REQUIRE(failover_task != nullptr);
      {
        ccf::http_client::CurlmLibuvContextSingleton singleton(
          uv_default_loop());
        failover_task->do_task();
      }
      uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    }

    void run_retry()
    {
      REQUIRE(retry_task != nullptr);
      {
        ccf::http_client::CurlmLibuvContextSingleton singleton(
          uv_default_loop());
        retry_task->do_task();
      }
      uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    }

    RequestNodeInfo request_info()
    {
      RequestNodeInfo info;
      info.quote_info.format = QuoteFormat::insecure_virtual;
      info.location = location;
      info.service_cert_der =
        ccf::crypto::cert_pem_to_der(fix.network.identity->cert);
      return info;
    }

    TResponse receive_gossip(VirtualRecoveryNode& sender)
    {
      GossipRequest req;
      req.info = sender.request_info();
      req.txid = sender.recovered_txid;
      return send_node_request(
        *frontend,
        "/recovery_decision_protocol/gossip",
        nlohmann::json(req),
        sender.fix.self_cert);
    }

    TResponse receive_vote(VirtualRecoveryNode& sender)
    {
      TaggedWithNodeInfo req;
      req.info = sender.request_info();
      return send_node_request(
        *frontend,
        "/recovery_decision_protocol/vote",
        nlohmann::json(req),
        sender.fix.self_cert);
    }

    TResponse receive_iamopen(VirtualRecoveryNode& sender)
    {
      auto ro = sender.fix.network.tables->create_read_only_tx();
      const auto& req = sender.fix.rdp().get_iamopen_request(ro);
      return send_node_request(
        *frontend,
        "/recovery_decision_protocol/iamopen",
        nlohmann::json(req),
        sender.fix.self_cert);
    }

    TResponse receive_timeout()
    {
      return send_node_request(
        *frontend,
        "/recovery_decision_protocol/timeout",
        nullptr,
        fix.self_cert);
    }

    StateMachine current_sm_state()
    {
      auto ro = fix.network.tables->create_read_only_tx();
      auto state =
        ro.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)->get();
      REQUIRE(state.has_value());
      return state.value();
    }
  };
}

TEST_CASE("Recovery trace quorum open complete")
{
  drain_main_job_board();
  ScopedRdpTraceCapture trace_capture("quorum_open_complete", 3);

  const std::vector<sealing_recovery::Location> locations = {
    {"node0", "127.0.0.1:1"},
    {"node1", "127.0.0.1:1"},
    {"node2", "127.0.0.1:1"}};
  const auto prev_cert =
    make_self_signed_cert(ccf::crypto::make_ec_key_pair(), "CN=PrevService");

  VirtualRecoveryNode n0(locations, 0, ccf::TxID{2, 5}, prev_cert);
  // Configure node1 with failover_timeout = 0ms so the traced quorum scenario
  // also exercises start_failover_timers() skip and stop_timers() with a null
  // failover_task when node1 stops timers in JOINING.
  VirtualRecoveryNode n1(locations, 1, ccf::TxID{2, 5}, prev_cert, "0ms");
  VirtualRecoveryNode n2(locations, 2, ccf::TxID{2, 5}, prev_cert, "30000ms");
  std::vector<VirtualRecoveryNode*> nodes = {&n0, &n1, &n2};

  for (auto* node : nodes)
  {
    node->start();
  }

  // Round 1: gossip broadcast and delivery (including duplicate gossip).
  for (auto* node : nodes)
  {
    node->run_retry();
  }
  // Exercise failover_task firing while GOSSIPING (dispatches timeout via
  // curl).
  n2.run_failover_task();
  CHECK(n0.receive_gossip(n0).status == HTTP_STATUS_NO_CONTENT);
  // Second retry from n0 sends another gossip copy so duplicate delivery is
  // causally justified in the Lean trace model.
  n0.run_retry();
  CHECK(n0.receive_gossip(n0).status == HTTP_STATUS_NO_CONTENT);

  for (auto* receiver : nodes)
  {
    for (auto* sender : nodes)
    {
      if (receiver == &n0 && sender == &n0)
      {
        continue;
      }
      CHECK(receiver->receive_gossip(*sender).status == HTTP_STATUS_NO_CONTENT);
    }
    CHECK(receiver->current_sm_state() == StateMachine::VOTING);
  }

  // Round 2: voting broadcast -> node2 opens via Quorum.
  for (auto* node : nodes)
  {
    node->run_retry();
  }
  CHECK(n2.receive_vote(n0).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n2.receive_vote(n1).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n2.current_sm_state() == StateMachine::OPENING);

  // Round 3: node2 broadcasts IAmOpen -> node0 and node1 join and stop timers.
  n2.run_retry();
  CHECK(n0.receive_iamopen(n2).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n1.receive_iamopen(n2).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n0.current_sm_state() == StateMachine::JOINING);
  CHECK(n1.current_sm_state() == StateMachine::JOINING);
  CHECK(n0.fix.runtime_control.restart_count == 1);
  CHECK(n1.fix.runtime_control.restart_count == 1);

  // Running retry_task in JOINING stops timers cleanly (L550-555).
  n0.run_retry();
  n1.run_retry();
  CHECK(n0.retry_task->is_cancelled());
  CHECK(n1.retry_task->is_cancelled());

  // Round 4: node2 advances timeout lane through OPENING -> OPEN, then hits
  // the OPEN case in advance() on a subsequent timeout, then stops timers.
  CHECK(n2.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n2.current_sm_state() == StateMachine::OPENING);
  CHECK(n2.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n2.current_sm_state() == StateMachine::OPENING);
  CHECK(n2.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n2.current_sm_state() == StateMachine::OPEN);
  CHECK(n2.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n2.current_sm_state() == StateMachine::OPEN);

  n2.run_failover_task();
  CHECK(n2.failover_task->is_cancelled());
  CHECK(n2.retry_task->is_cancelled());
}

TEST_CASE("Recovery trace voting zero votes timeout failover")
{
  drain_main_job_board();
  ScopedRdpTraceCapture trace_capture("voting_zero_votes_timeout_failover", 2);

  // 3 expected locations, only 2 active (node2 offline).
  const std::vector<sealing_recovery::Location> locations = {
    {"node0", "127.0.0.1:1"},
    {"node1", "127.0.0.1:1"},
    {"node2", "127.0.0.1:1"}};
  const auto prev_cert =
    make_self_signed_cert(ccf::crypto::make_ec_key_pair(), "CN=PrevService");

  VirtualRecoveryNode n0(locations, 0, ccf::TxID{2, 5}, prev_cert);
  VirtualRecoveryNode n1(locations, 1, ccf::TxID{2, 10}, prev_cert);

  n0.start();
  n1.start();

  // Both broadcast gossips and exchange them (2 < 3 expected).
  n0.run_retry();
  n1.run_retry();
  CHECK(n0.receive_gossip(n0).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n0.receive_gossip(n1).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n1.receive_gossip(n0).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n1.receive_gossip(n1).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n0.current_sm_state() == StateMachine::GOSSIPING);
  CHECK(n1.current_sm_state() == StateMachine::GOSSIPING);

  // Both timeout GOSSIPING -> VOTING and choose node1 (2.10 > 2.5).
  CHECK(n0.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n1.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n0.current_sm_state() == StateMachine::VOTING);
  CHECK(n1.current_sm_state() == StateMachine::VOTING);

  // Safety check (L334-344): node0 has 0 votes for itself and times out in
  // VOTING. It must refuse to failover-open and keep both SMState and
  // TimeoutSMState in VOTING.
  CHECK(n0.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n0.current_sm_state() == StateMachine::VOTING);
  {
    auto ro = n0.fix.network.tables->create_read_only_tx();
    CHECK(
      ro.ro<TimeoutSMState>(Tables::RECOVERY_DECISION_PROTOCOL_TIMEOUT_SM_STATE)
        ->get() == StateMachine::VOTING);
  }

  // Both broadcast votes for node1. node1 receives 1 vote (< quorum of 2) and
  // opens via Failover on its VOTING timeout.
  n0.run_retry();
  n1.run_retry();
  CHECK(n1.receive_vote(n0).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n1.current_sm_state() == StateMachine::VOTING);
  CHECK(n1.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n1.current_sm_state() == StateMachine::OPENING);

  // node1 broadcasts IAmOpen; node0 joins and stops timers; node1 completes to
  // OPEN and stops timers.
  n1.run_retry();
  CHECK(n0.receive_iamopen(n1).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n0.current_sm_state() == StateMachine::JOINING);
  CHECK(n0.fix.runtime_control.restart_count == 1);
  n0.run_retry();
  CHECK(n0.retry_task->is_cancelled());

  CHECK(n1.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n1.current_sm_state() == StateMachine::OPEN);
  CHECK(n1.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n1.current_sm_state() == StateMachine::OPEN);
  n1.run_retry();
  CHECK(n1.retry_task->is_cancelled());
}

TEST_CASE("Recovery trace protocol rejections")
{
  drain_main_job_board();
  ScopedRdpTraceCapture trace_capture("protocol_rejections", 3);

  const std::vector<sealing_recovery::Location> locations = {
    {"node0", "127.0.0.1:1"},
    {"node1", "127.0.0.1:1"},
    {"node2", "127.0.0.1:1"}};
  const auto prev_cert =
    make_self_signed_cert(ccf::crypto::make_ec_key_pair(), "CN=PrevService");

  VirtualRecoveryNode n0(locations, 0, ccf::TxID{2, 5}, prev_cert);
  VirtualRecoveryNode n1(locations, 1, ccf::TxID{2, 5}, prev_cert);
  VirtualRecoveryNode n2(locations, 2, ccf::TxID{2, 5}, prev_cert);
  std::vector<VirtualRecoveryNode*> nodes = {&n0, &n1, &n2};

  const auto other_trusted_cert =
    make_self_signed_cert(ccf::crypto::make_ec_key_pair(), "CN=OtherTrusted");
  const auto other_trusted_id = n0.fix.add_trusted_node(other_trusted_cert);
  const auto rogue_cert =
    make_self_signed_cert(ccf::crypto::make_ec_key_pair(), "CN=RoguePeer");

  for (auto* node : nodes)
  {
    node->start();
  }

  // Empty-gossip GOSSIPING timeout throws std::logic_error (L298-301), caught
  // by /timeout (L387-395) without committing or corrupting the trace.
  {
    const auto resp = n0.receive_timeout();
    CHECK(resp.status == HTTP_STATUS_INTERNAL_SERVER_ERROR);
    const auto err = parse_error_json(resp)["error"];
    CHECK(err["code"] == ccf::errors::InternalError);
    CHECK(err["message"].get<std::string>().contains(
      "No gossip addresses provided yet"));
  }

  // Invalid quote rejections (L70-80) on gossip, vote, and iamopen do not
  // commit or perturb the trace.
  n0.node_op->verify_quote_override =
    QuoteVerificationResult::FailedInvalidQuotedPublicKey;
  {
    CHECK(n0.receive_gossip(n1).status == HTTP_STATUS_UNAUTHORIZED);
    CHECK(n0.receive_vote(n1).status == HTTP_STATUS_UNAUTHORIZED);
    CHECK(n0.receive_iamopen(n1).status == HTTP_STATUS_UNAUTHORIZED);
  }
  n0.node_op->verify_quote_override = QuoteVerificationResult::Verified;

  // Unknown-primary (L358-365) and non-primary (L368-377) /timeout rejections
  // do not commit or perturb the trace.
  {
    n0.node_op->primary_override = std::optional<ccf::NodeId>(std::nullopt);
    CHECK(n0.receive_timeout().status == HTTP_STATUS_INTERNAL_SERVER_ERROR);

    n0.node_op->primary_override =
      std::optional<ccf::NodeId>(n0.fix.node_state->get_node_id());
    CHECK(
      send_node_request(
        *n0.frontend,
        "/recovery_decision_protocol/timeout",
        nullptr,
        other_trusted_cert)
        .status == HTTP_STATUS_INTERNAL_SERVER_ERROR);
    CHECK(other_trusted_id != n0.fix.node_state->get_node_id());
  }

  // Round 1: gossip broadcast; deliver n1's gossip to n0, then verify changed
  // sender public key for "node1" is rejected on gossip, vote, and iamopen
  // (L99-109) without affecting the trace.
  for (auto* node : nodes)
  {
    node->run_retry();
  }
  CHECK(n0.receive_gossip(n1).status == HTTP_STATUS_NO_CONTENT);
  {
    GossipRequest bad_gossip;
    bad_gossip.info = n1.request_info();
    bad_gossip.txid = n1.recovered_txid;
    CHECK(
      send_node_request(
        *n0.frontend,
        "/recovery_decision_protocol/gossip",
        nlohmann::json(bad_gossip),
        rogue_cert)
        .status == HTTP_STATUS_BAD_REQUEST);

    TaggedWithNodeInfo bad_vote;
    bad_vote.info = n1.request_info();
    CHECK(
      send_node_request(
        *n0.frontend,
        "/recovery_decision_protocol/vote",
        nlohmann::json(bad_vote),
        rogue_cert)
        .status == HTTP_STATUS_BAD_REQUEST);

    auto ro = n1.fix.network.tables->create_read_only_tx();
    const auto& bad_iamopen = n1.fix.rdp().get_iamopen_request(ro);
    CHECK(
      send_node_request(
        *n0.frontend,
        "/recovery_decision_protocol/iamopen",
        nlohmann::json(bad_iamopen),
        rogue_cert)
        .status == HTTP_STATUS_BAD_REQUEST);
  }

  for (auto* receiver : nodes)
  {
    for (auto* sender : nodes)
    {
      if (receiver == &n0 && sender == &n1)
      {
        continue;
      }
      CHECK(receiver->receive_gossip(*sender).status == HTTP_STATUS_NO_CONTENT);
    }
    CHECK(receiver->current_sm_state() == StateMachine::VOTING);
  }
  // Compact n0's VOTING write so the global SMState hook also runs for a
  // non-GOSSIPING value inside the traced scenario (L215).
  n0.fix.network.tables->compact(n0.fix.network.tables->current_version());

  // Post-vote gossip rejection on n0 (L195-205) leaves trace intact.
  CHECK(n0.receive_gossip(n1).status == HTTP_STATUS_INTERNAL_SERVER_ERROR);

  // Round 2: voting -> node2 opens via Quorum.
  for (auto* node : nodes)
  {
    node->run_retry();
  }
  CHECK(n2.receive_vote(n0).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n2.receive_vote(n1).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n2.current_sm_state() == StateMachine::OPENING);

  // Already-open IAmOpen rejection while OPENING (L266-298) leaves trace
  // intact.
  CHECK(n2.receive_iamopen(n1).status == HTTP_STATUS_BAD_REQUEST);

  // Round 3: node2 broadcasts IAmOpen; node0 and node1 join and stop timers.
  n2.run_retry();
  CHECK(n0.receive_iamopen(n2).status == HTTP_STATUS_NO_CONTENT);
  CHECK(n1.receive_iamopen(n2).status == HTTP_STATUS_NO_CONTENT);
  n0.run_retry();
  n1.run_retry();
  CHECK(n0.retry_task->is_cancelled());
  CHECK(n1.retry_task->is_cancelled());

  // Round 4: node2 advances OPENING -> OPEN, rejects IAmOpen while OPEN
  // (L266-298), then handles OPEN timeout and stops timers.
  CHECK(n2.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n2.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n2.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n2.current_sm_state() == StateMachine::OPEN);
  CHECK(n2.receive_iamopen(n1).status == HTTP_STATUS_BAD_REQUEST);
  CHECK(n2.receive_timeout().status == HTTP_STATUS_OK);
  CHECK(n2.current_sm_state() == StateMachine::OPEN);
  n2.run_retry();
  CHECK(n2.retry_task->is_cancelled());
}

int main(int argc, char** argv)
{
  ccf::logger::config::default_init();
  curl_global_init(CURL_GLOBAL_DEFAULT);
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  const int res = context.run();
  curl_global_cleanup();
  return res;
}
