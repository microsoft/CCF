// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/verifier.h"
#include "ds/internal_logger.h"
#include "ds/ring_buffer.h"
#include "kv/test/null_encryptor.h"
#include "node/node_state.h"
#include "node/rpc/abstract_rpc_sessions.h"
#include "node/rpc/node_frontend.h"
#include "node/rpc_context_impl.h"
#include "node/runtime_control.h"
#include "node_stub.h"
#include "tasks/task_system.h"

#include <cstdlib>
#include <doctest/doctest.h>
#include <filesystem>

using namespace ccf;
using nlohmann::json;

namespace
{
  using State = recovery_decision_protocol::StateMachine;

  class RecoveryTestEnvironment
  {
    struct TraceLogger : public ccf::logger::AbstractLogger
    {
      std::vector<json>& events;

      TraceLogger(std::vector<json>& events_) : events(events_) {}

      void write(const ccf::logger::LogLine& line) override
      {
        constexpr std::string_view marker = "RDP_TRACE ";
        if (line.msg.starts_with(marker))
        {
          events.push_back(json::parse(line.msg.substr(marker.size())));
        }
      }
    };

    const ccf::LoggerLevel previous_log_level = ccf::logger::config::level();
    const ccf::pal::Platform previous_platform = ccf::pal::platform;
    ccf::logger::AbstractLogger* trace_logger = nullptr;

  public:
    const std::string valid_from = ccf::ds::to_x509_time_string(
      std::chrono::system_clock::now() - std::chrono::hours(24));
    const ccf::crypto::Pem service_cert =
      ccf::crypto::make_ec_key_pair()->self_sign(
        "CN=Recovery test",
        valid_from,
        ccf::crypto::compute_cert_valid_to_string(valid_from, 2));
    std::string snapshot_directory =
      (std::filesystem::current_path() / "ccf_recovery_test_XXXXXX").string();
    std::vector<json> events;

    RecoveryTestEnvironment()
    {
      REQUIRE(mkdtemp(snapshot_directory.data()) != nullptr);
      auto logger = std::make_unique<TraceLogger>(events);
      trace_logger = logger.get();
      ccf::logger::config::loggers().push_back(std::move(logger));
      ccf::logger::config::level() = ccf::LoggerLevel::INFO;
      ccf::pal::platform = ccf::pal::Platform::Virtual;
      ccf::pal::emit_virtual_measurement();
    }

    ~RecoveryTestEnvironment()
    {
      std::erase_if(ccf::logger::config::loggers(), [this](const auto& logger) {
        return logger.get() == trace_logger;
      });
      ccf::logger::config::level() = previous_log_level;
      ccf::pal::platform = previous_platform;
      std::filesystem::remove(
        ccf::pal::virtual_attestation_path("measurement"));
      std::filesystem::remove(
        ccf::pal::virtual_attestation_path("attestation"));
      std::filesystem::remove(snapshot_directory);
    }
  };

  class RecoveryTestRuntimeControl : public AbstractRuntimeControl
  {
  public:
    size_t restarts = 0;

    void report_stopped() override {}

    void report_fatal_error(const std::string& /*message*/) override {}

    void request_restart() override
    {
      ++restarts;
    }
  };

  class RecoveryTestRPCSessions : public AbstractRPCSessions
  {
  public:
    bool reply_async(
      int64_t /*id*/,
      bool /*terminate_after_reply*/,
      std::vector<uint8_t>&& /*data*/) override
    {
      return true;
    }

    SessionMetrics get_session_metrics() override
    {
      return {};
    }

    void set_node_cert(
      const ccf::crypto::Pem& /*cert*/, const ccf::crypto::Pem& /*pk*/) override
    {}

    void set_network_cert(
      const ccf::crypto::Pem& /*cert*/, const ccf::crypto::Pem& /*pk*/) override
    {}

    void update_listening_interface_options(
      const NodeInfoNetwork& /*node_info*/) override
    {}

    void set_custom_protocol_subsystem(
      std::shared_ptr<CustomProtocolSubsystem> /*cpss*/) override
    {}

    void set_commit_callbacks_subsystem(
      std::shared_ptr<CommitCallbackSubsystem> /*ccss*/) override
    {}
  };

  class RecoveryTestNodeOperation : public StubNodeOperation
  {
    RecoveryDecisionProtocolSubsystem& protocol;

  public:
    RecoveryTestNodeOperation(RecoveryDecisionProtocolSubsystem& protocol_) :
      protocol(protocol_)
    {}

    RecoveryDecisionProtocolSubsystem& recovery_decision_protocol() override
    {
      return protocol;
    }
  };

  class RecoveryTestFrontend : public NodeRpcFrontend
  {
  public:
    using NodeRpcFrontend::NodeRpcFrontend;

    ccf::endpoints::EndpointRegistry& get_node_endpoints()
    {
      return node_endpoints;
    }
  };

  struct RecoveryTestContext : public AbstractNodeContext
  {
    [[nodiscard]] ccf::NodeId get_node_id() const override
    {
      return ccf::kv::test::PrimaryNodeId;
    }
  };

  struct RecoveryProtocolFixture
  {
    RecoveryTestEnvironment environment;
    NetworkState network = []() {
      NetworkState result;
      result.ledger_secrets = std::make_shared<LedgerSecrets>();
      result.ledger_secrets->init();
      return result;
    }();
    RecoveryTestContext context;
    ringbuffer::TestBuffer inside{1 << 20};
    ringbuffer::TestBuffer outside{1 << 20};
    ringbuffer::Circuit circuit{inside.bd, outside.bd};
    ringbuffer::WriterFactory writers{circuit};
    std::shared_ptr<RPCMap> rpc_map = std::make_shared<RPCMap>();
    std::shared_ptr<RecoveryTestRPCSessions> sessions =
      std::make_shared<RecoveryTestRPCSessions>();
    RecoveryTestRuntimeControl runtime_control;
    NodeState node{
      writers,
      network,
      sessions,
      ccf::crypto::service_identity_curve_choice,
      runtime_control};
    std::shared_ptr<RecoveryTestNodeOperation> operation =
      std::make_shared<RecoveryTestNodeOperation>(
        node.get_recovery_decision_protocol());
    std::shared_ptr<RecoveryTestFrontend> frontend;
    std::vector<json> startup_events;

    RecoveryProtocolFixture()
    {
      context.install_subsystem(operation);
      context.install_subsystem(std::make_shared<StubGovernanceEffects>());
      context.install_subsystem(std::make_shared<StubNodeStateCache>());
      context.install_subsystem(
        std::make_shared<NodeConfigurationSubsystem>(node));
      frontend = std::make_shared<RecoveryTestFrontend>(network, context);
      rpc_map->register_frontend<ActorsType::nodes>(frontend);
      node.initialize({}, rpc_map, sessions, nullptr, nullptr, 100, 100);

      StartupConfig config;
      config.startup_host_time = environment.valid_from;
      config.recover.previous_service_identity = environment.service_cert.raw();
      config.snapshots.directory = environment.snapshot_directory;
      config.sealing_recovery = SealingRecoveryConfig{
        .location = {"joiner", "127.0.0.1:0"},
        .recovery_decision_protocol =
          RecoveryDecisionProtocolConfig{
            .expected_locations =
              {{"joiner", "127.0.0.1:0"}, {"opener", "127.0.0.1:0"}},
            .message_retry_timeout = {"100ms"},
            .failover_timeout = {"0ms"},
          },
      };
      node.create(StartType::Recover, config);
      network.tables->set_history(nullptr);
      network.tables->set_encryptor(
        std::make_shared<ccf::kv::NullTxEncryptor>());
      network.tables->set_readiness(ccf::kv::StoreReadiness::Ready);

      auto tx = network.tables->create_tx();
      tx.rw<PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
        ->put(environment.service_cert);
      node.get_recovery_decision_protocol().try_start(tx, true);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      network.tables->compact(network.tables->current_version());

      // Sending requires an HTTP client, so the retry task is not run here
      ccf::tasks::tick(std::chrono::milliseconds(0));
      auto retry = ccf::tasks::get_main_job_board().get_task();
      REQUIRE(retry != nullptr);
      REQUIRE(retry->get_name() == "RecoveryDecisionProtocolRetry");
      retry->cancel_task();
      ccf::tasks::tick(std::chrono::milliseconds(100));
      REQUIRE(ccf::tasks::get_main_job_board().get_task() == nullptr);
      REQUIRE(runtime_control.restarts == 0);

      startup_events = std::move(environment.events);
      environment.events.clear();
    }

    std::unique_ptr<EndpointContextImpl> execute(
      const std::shared_ptr<RpcContext>& rpc_ctx)
    {
      auto args = std::make_unique<EndpointContextImpl>(
        rpc_ctx, network.tables->create_tx_ptr());
      auto caller = std::make_unique<NodeCertAuthnIdentity>();
      caller->node_id = ccf::kv::test::PrimaryNodeId;
      args->caller = std::move(caller);
      auto& registry = frontend->get_node_endpoints();
      auto endpoint = registry.find_endpoint(args->tx, *rpc_ctx);
      REQUIRE(endpoint != nullptr);
      registry.execute_endpoint(endpoint, *args);
      return args;
    }

    std::unique_ptr<EndpointContextImpl> prepare(
      const std::string& path, const json& params)
    {
      ::http::Request request(path, HTTP_PUT);
      const auto body = params.dump();
      request.set_body(body);
      auto session = std::make_shared<SessionContext>(
        InvalidSessionId,
        ccf::crypto::cert_pem_to_der(environment.service_cert));
      return execute(make_rpc_context(session, request.build_request()));
    }

    // Re-executes a request, as the frontend does after a commit conflict
    std::unique_ptr<EndpointContextImpl> retry(EndpointContextImpl& previous)
    {
      auto* rpc_ctx =
        dynamic_cast<ccf::RpcContextImpl*>(previous.rpc_ctx.get());
      REQUIRE(rpc_ctx != nullptr);
      rpc_ctx->reset_response();
      return execute(previous.rpc_ctx);
    }

    void commit(EndpointContextImpl& args)
    {
      REQUIRE(args.owned_tx->commit() == ccf::kv::CommitResult::SUCCESS);
      network.tables->compact(network.tables->current_version());
    }

    recovery_decision_protocol::RequestNodeInfo node_info(
      const std::string& name)
    {
      return {
        .quote_info = {},
        .location = {name, "127.0.0.1:0"},
        .service_cert_der =
          ccf::crypto::cert_pem_to_der(environment.service_cert),
      };
    }

    json gossip(const std::string& name, ccf::TxID txid)
    {
      recovery_decision_protocol::GossipRequest request;
      request.info = node_info(name);
      request.txid = txid;
      return request;
    }

    json vote(const std::string& name)
    {
      return recovery_decision_protocol::TaggedWithNodeInfo{
        .info = node_info(name)};
    }

    json iamopen(const std::string& name)
    {
      recovery_decision_protocol::IAmOpenRequest request;
      request.info = node_info(name);
      request.prev_service_fingerprint =
        recovery_decision_protocol::service_fingerprint_from_pem(
          environment.service_cert);
      request.txid = {1, 1};
      return request;
    }

    // Adds the identifier that traced senders attach to protocol messages.
    // Every build must accept messages with or without it.
    static json traced(json message, const std::string& message_id)
    {
      message["trace_message_id"] = message_id;
      return message;
    }

    std::optional<State> phase()
    {
      auto tx = network.tables->create_read_only_tx();
      return tx
        .ro<recovery_decision_protocol::SMState>(
          Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
        ->get();
    }
  };

  void check_trace_events(
    RecoveryProtocolFixture& fixture,
    [[maybe_unused]] const std::vector<json>& expected)
  {
#ifdef CCF_RECOVERY_TRACE
    REQUIRE(fixture.environment.events.size() == expected.size());
    for (size_t i = 0; i < expected.size(); ++i)
    {
      INFO(fixture.environment.events[i].dump());
      for (const auto& [key, value] : expected[i].items())
      {
        CHECK(fixture.environment.events[i][key] == value);
      }
    }
#else
    CHECK(fixture.environment.events.empty());
#endif
    fixture.environment.events.clear();
  }
}

TEST_CASE("Recovery tracing records protocol initialisation")
{
  RecoveryProtocolFixture fixture;

#ifdef CCF_RECOVERY_TRACE
  const auto instance =
    recovery_decision_protocol::service_fingerprint_from_pem(
      fixture.environment.service_cert);
  REQUIRE(fixture.startup_events.size() == 2);
  CHECK(fixture.startup_events[0]["kind"] == "start");
  CHECK(fixture.startup_events[0]["pre"] == "GOSSIPING");
  CHECK(fixture.startup_events[0]["post"] == "GOSSIPING");
  CHECK(fixture.startup_events[1]["kind"] == "committed");
  CHECK(fixture.startup_events[1]["post"] == "GOSSIPING");
  CHECK(fixture.startup_events[1].contains("version"));
  for (size_t i = 0; i < fixture.startup_events.size(); ++i)
  {
    const auto& event = fixture.startup_events[i];
    CHECK(event["instance"] == instance);
    CHECK(event["node"] == "joiner");
    CHECK(event["expected_locations"] == json::array({"joiner", "opener"}));
    CHECK(event["sequence"] == i);
  }
#else
  CHECK(fixture.startup_events.empty());
#endif
}

TEST_CASE("Recovery tracing records observed transitions and effects")
{
  RecoveryProtocolFixture fixture;

  auto gossip = fixture.prepare(
    "recovery_decision_protocol/gossip",
    RecoveryProtocolFixture::traced(
      fixture.gossip("opener", {1, 1}), "opener:0"));
  REQUIRE(gossip->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  fixture.commit(*gossip);
  check_trace_events(
    fixture,
    {{
      {"kind", "gossip_accepted"},
      {"sequence", 2},
      {"attempt", 0},
      {"caused_by", "opener:0"},
      {"source", "opener"},
      {"view", 1},
      {"seqno", 1},
      {"pre", "GOSSIPING"},
      {"post", "GOSSIPING"},
      {"pre_timeout", "GOSSIPING"},
      {"post_timeout", "GOSSIPING"},
      {"gossips",
       json::array({{{"location", "opener"}, {"view", 1}, {"seqno", 1}}})},
    }});

  auto timeout =
    fixture.prepare("recovery_decision_protocol/timeout", json::object());
  REQUIRE(timeout->rpc_ctx->get_response_status() == HTTP_STATUS_OK);
  fixture.commit(*timeout);
  check_trace_events(
    fixture,
    {{
       {"kind", "timeout"},
       {"attempt", 1},
       {"pre", "GOSSIPING"},
       {"post", "VOTING"},
       {"pre_timeout", "GOSSIPING"},
       {"post_timeout", "VOTING"},
       {"gossips",
        json::array({{{"location", "opener"}, {"view", 1}, {"seqno", 1}}})},
       {"chosen", "opener"},
     },
     {
       {"kind", "committed"},
       {"post", "VOTING"},
     }});

  auto vote =
    fixture.prepare("recovery_decision_protocol/vote", fixture.vote("opener"));
  REQUIRE(vote->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  fixture.commit(*vote);
  // Messages without an identifier are handled as before and are recorded
  // without a cause
  check_trace_events(
    fixture,
    {{
      {"kind", "vote_accepted"},
      {"attempt", 2},
      {"caused_by", nullptr},
      {"source", "opener"},
      {"pre", "VOTING"},
      {"post", "VOTING"},
      {"pre_timeout", "VOTING"},
      {"post_timeout", "VOTING"},
      {"votes", json::array({"opener"})},
    }});

  // The restart is requested while the transaction executes, whether or not
  // tracing is enabled
  auto iamopen = fixture.prepare(
    "recovery_decision_protocol/iamopen",
    RecoveryProtocolFixture::traced(fixture.iamopen("opener"), "opener:1"));
  REQUIRE(iamopen->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  CHECK(fixture.runtime_control.restarts == 1);
  fixture.commit(*iamopen);
  check_trace_events(
    fixture,
    {{
       {"kind", "iamopen_accepted"},
       {"attempt", 3},
       {"caused_by", "opener:1"},
       {"source", "opener"},
       {"pre", "VOTING"},
       {"post", "JOINING"},
       {"pre_timeout", "VOTING"},
       {"post_timeout", "VOTING"},
       {"chosen", "opener"},
     },
     {
       {"kind", "join_restart"},
       {"attempt", 3},
       {"pre", "JOINING"},
       {"post", "JOINING"},
       {"chosen", "opener"},
     },
     {
       {"kind", "committed"},
       {"post", "JOINING"},
     }});

  // Each later advance in Joining requests another restart
  timeout =
    fixture.prepare("recovery_decision_protocol/timeout", json::object());
  REQUIRE(timeout->rpc_ctx->get_response_status() == HTTP_STATUS_OK);
  CHECK(fixture.runtime_control.restarts == 2);
  fixture.commit(*timeout);
  check_trace_events(
    fixture,
    {{
       {"kind", "timeout"},
       {"attempt", 4},
       {"pre", "JOINING"},
       {"post", "JOINING"},
       {"pre_timeout", "VOTING"},
       {"post_timeout", "OPENING"},
       {"chosen", "opener"},
     },
     {
       {"kind", "join_restart"},
       {"attempt", 4},
       {"chosen", "opener"},
     }});
  CHECK(fixture.phase() == State::JOINING);
}

TEST_CASE("Recovery tracing records retry observations")
{
  RecoveryProtocolFixture fixture;

  // Restart the retry timer, then let it observe a Joining node, which stops
  // it before anything is sent
  for (const auto phase : {State::GOSSIPING, State::JOINING})
  {
    auto tx = fixture.network.tables->create_tx();
    tx.rw<recovery_decision_protocol::SMState>(
        Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
      ->put(phase);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    fixture.network.tables->compact(fixture.network.tables->current_version());
  }
  ccf::tasks::tick(std::chrono::milliseconds(0));
  auto retry = ccf::tasks::get_main_job_board().get_task();
  REQUIRE(retry != nullptr);
  REQUIRE(retry->get_name() == "RecoveryDecisionProtocolRetry");
  retry->do_task();
  ccf::tasks::tick(std::chrono::milliseconds(100));
  CHECK(ccf::tasks::get_main_job_board().get_task() == nullptr);

  check_trace_events(
    fixture,
    {{
       {"kind", "committed"},
       {"post", "GOSSIPING"},
     },
     {
       {"kind", "committed"},
       {"post", "JOINING"},
     },
     {
       {"kind", "retry"},
       {"batch", 0},
       {"pre", "JOINING"},
       {"post", "JOINING"},
     }});
}

TEST_CASE("Recovery tracing records each conflicting execution attempt")
{
  RecoveryProtocolFixture fixture;

  auto first = fixture.prepare(
    "recovery_decision_protocol/gossip",
    RecoveryProtocolFixture::traced(
      fixture.gossip("opener", {1, 1}), "opener:5"));
  REQUIRE(first->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);

  {
    auto concurrent = fixture.network.tables->create_tx();
    concurrent
      .rw<recovery_decision_protocol::Gossips>(
        Tables::RECOVERY_DECISION_PROTOCOL_GOSSIPS)
      ->put("joiner", {2, 5});
    REQUIRE(concurrent.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  REQUIRE(first->owned_tx->commit() == ccf::kv::CommitResult::FAIL_CONFLICT);

  auto second = fixture.retry(*first);
  REQUIRE(second->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  fixture.commit(*second);

  // Both attempts record the same cause. Only the last execution of a request
  // can commit, but nothing marks the superseded attempt.
  check_trace_events(
    fixture,
    {{
       {"kind", "gossip_accepted"},
       {"attempt", 0},
       {"caused_by", "opener:5"},
       {"post", "GOSSIPING"},
       {"gossips",
        json::array({{{"location", "opener"}, {"view", 1}, {"seqno", 1}}})},
     },
     {
       {"kind", "gossip_accepted"},
       {"attempt", 1},
       {"caused_by", "opener:5"},
       {"post", "VOTING"},
       {"gossips",
        json::array(
          {{{"location", "joiner"}, {"view", 2}, {"seqno", 5}},
           {{"location", "opener"}, {"view", 1}, {"seqno", 1}}})},
       {"chosen", "joiner"},
     },
     {
       {"kind", "committed"},
       {"post", "VOTING"},
     }});
}

TEST_CASE("Recovery tracing adds no read dependencies")
{
  RecoveryProtocolFixture fixture;

  {
    auto existing = fixture.network.tables->create_tx();
    existing
      .rw<recovery_decision_protocol::Gossips>(
        Tables::RECOVERY_DECISION_PROTOCOL_GOSSIPS)
      ->put("joiner", {2, 5});
    existing
      .rw<recovery_decision_protocol::Votes>(
        Tables::RECOVERY_DECISION_PROTOCOL_VOTES)
      ->insert("joiner");
    REQUIRE(existing.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // A vote while gossiping does not read the votes, so a concurrent vote must
  // not conflict with it
  auto vote =
    fixture.prepare("recovery_decision_protocol/vote", fixture.vote("opener"));
  REQUIRE(vote->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  {
    auto concurrent = fixture.network.tables->create_tx();
    concurrent
      .rw<recovery_decision_protocol::Votes>(
        Tables::RECOVERY_DECISION_PROTOCOL_VOTES)
      ->insert("other");
    REQUIRE(concurrent.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  CHECK(vote->owned_tx->commit() == ccf::kv::CommitResult::SUCCESS);

  // An IAmOpen does not read the gossips, so a concurrent gossip must not
  // conflict with it
  auto iamopen = fixture.prepare(
    "recovery_decision_protocol/iamopen", fixture.iamopen("opener"));
  REQUIRE(iamopen->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  CHECK(fixture.runtime_control.restarts == 1);
  {
    auto concurrent = fixture.network.tables->create_tx();
    concurrent
      .rw<recovery_decision_protocol::Gossips>(
        Tables::RECOVERY_DECISION_PROTOCOL_GOSSIPS)
      ->put("other", {3, 3});
    REQUIRE(concurrent.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  CHECK(iamopen->owned_tx->commit() == ccf::kv::CommitResult::SUCCESS);
  CHECK(fixture.phase() == State::JOINING);

  check_trace_events(
    fixture,
    {{
       {"kind", "vote_accepted"},
       {"attempt", 0},
       {"pre", "GOSSIPING"},
       {"post", "GOSSIPING"},
       {"gossips",
        json::array({{{"location", "joiner"}, {"view", 2}, {"seqno", 5}}})},
     },
     {
       {"kind", "iamopen_accepted"},
       {"attempt", 1},
       {"pre", "GOSSIPING"},
       {"post", "JOINING"},
       {"chosen", "opener"},
     },
     {
       {"kind", "join_restart"},
       {"attempt", 1},
     }});
}
