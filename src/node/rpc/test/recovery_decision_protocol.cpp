// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/verifier.h"
#include "ds/internal_logger.h"
#include "ds/ring_buffer.h"
#include "kv/test/null_encryptor.h"
#include "node/node_state.h"
#include "node/rpc/node_frontend.h"
#include "node_stub.h"
#include "tasks/task_system.h"

#include <array>
#include <cstdlib>
#include <doctest/doctest.h>
#include <filesystem>

using namespace ccf;
using nlohmann::json;

namespace
{
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

  class RecoveryTestNodeOperation : public StubNodeOperation
  {
    RecoveryDecisionProtocolSubsystem& protocol;

  public:
    size_t quote_verifications = 0;

    RecoveryTestNodeOperation(RecoveryDecisionProtocolSubsystem& protocol_) :
      protocol(protocol_)
    {}

    RecoveryDecisionProtocolSubsystem& recovery_decision_protocol() override
    {
      return protocol;
    }

    QuoteVerificationResult verify_quote(
      ccf::kv::ReadOnlyTx&,
      const QuoteInfo&,
      const std::vector<uint8_t>&,
      pal::PlatformAttestationMeasurement&,
      const std::optional<std::vector<uint8_t>>&,
      std::shared_ptr<NetworkIdentitySubsystemInterface>) override
    {
      ++quote_verifications;
      return QuoteVerificationResult::Verified;
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
    ccf::NodeId get_node_id() const override
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
    std::shared_ptr<RPCSessions> sessions =
      std::make_shared<RPCSessions>(writers, rpc_map);
    NodeState node{
      writers, network, sessions, ccf::crypto::service_identity_curve_choice};
    std::shared_ptr<RecoveryTestNodeOperation> operation =
      std::make_shared<RecoveryTestNodeOperation>(
        node.get_recovery_decision_protocol());
    std::shared_ptr<RecoveryTestFrontend> frontend;
    size_t restart_count = 0;

    RecoveryProtocolFixture()
    {
      context.install_subsystem(operation);
      context.install_subsystem(std::make_shared<StubGovernanceEffects>());
      context.install_subsystem(std::make_shared<StubNodeStateCache>());
      context.install_subsystem(
        std::make_shared<NodeConfigurationSubsystem>(node));
      frontend = std::make_shared<RecoveryTestFrontend>(network, context);
      rpc_map->register_frontend<ActorsType::nodes>(frontend);
      node.initialize(
        {}, rpc_map, sessions, nullptr, nullptr, nullptr, 100, 100);

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

      ccf::tasks::tick(std::chrono::milliseconds(0));
      auto retry = ccf::tasks::get_main_job_board().get_task();
      REQUIRE(retry != nullptr);
      REQUIRE(retry->get_name() == "RecoveryDecisionProtocolRetry");
      retry->cancel_task();
      ccf::tasks::tick(std::chrono::milliseconds(100));
      REQUIRE(ccf::tasks::get_main_job_board().get_task() == nullptr);
      REQUIRE(read_restarts() == 0);
      environment.events.clear();
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
      auto rpc_ctx = make_rpc_context(session, request.build_request());
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

    recovery_decision_protocol::IAmOpenRequest iamopen_request()
    {
      recovery_decision_protocol::IAmOpenRequest request;
      request.info.location = {"opener", "127.0.0.1:0"};
      request.info.service_cert_der =
        ccf::crypto::cert_pem_to_der(environment.service_cert);
      request.prev_service_fingerprint =
        recovery_decision_protocol::service_fingerprint_from_pem(
          environment.service_cert);
      request.txid = {1, 1};
      request.message_id = "opener:1";
      return request;
    }

    size_t read_restarts()
    {
      for (size_t i = 0; i < 2; ++i)
      {
        circuit.read_from_inside().read(
          -1, [&](ringbuffer::Message message, const uint8_t*, size_t) {
            if (message == AdminMessage::restart)
            {
              ++restart_count;
            }
          });
      }
      return restart_count;
    }
  };
}

TEST_CASE("Recovery protocol message IDs are required")
{
  RecoveryProtocolFixture fixture;
  auto iamopen = fixture.iamopen_request();
  recovery_decision_protocol::GossipRequest gossip;
  gossip.info = iamopen.info;
  gossip.txid = iamopen.txid;
  recovery_decision_protocol::TaggedWithNodeInfo vote{
    .info = iamopen.info, .message_id = "opener:1"};
  const std::array<std::pair<std::string, json>, 3> requests = {
    {{"gossip", gossip}, {"vote", vote}, {"iamopen", iamopen}}};

  {
    auto params = json(gossip);
    params.erase("message_id");
    CHECK_THROWS_AS(
      params.get<recovery_decision_protocol::GossipRequest>(),
      ccf::JsonParseError);
  }
  {
    auto params = json(vote);
    params.erase("message_id");
    CHECK_THROWS_AS(
      params.get<recovery_decision_protocol::TaggedWithNodeInfo>(),
      ccf::JsonParseError);
  }
  {
    auto params = json(iamopen);
    params.erase("message_id");
    CHECK_THROWS_AS(
      params.get<recovery_decision_protocol::IAmOpenRequest>(),
      ccf::JsonParseError);
  }

  for (const auto& [kind, request] : requests)
  {
    for (const auto& id : {"", "opener:1"})
    {
      INFO(kind, ": ", id);
      json params = request;
      params["message_id"] = id;
      const auto verified_before = fixture.operation->quote_verifications;
      auto args = fixture.prepare("recovery_decision_protocol/" + kind, params);
      if (std::string_view(id).empty())
      {
        CHECK(args->rpc_ctx->get_response_status() == HTTP_STATUS_BAD_REQUEST);
        if (args->rpc_ctx->get_response_status() == HTTP_STATUS_BAD_REQUEST)
        {
          const auto error = json::parse(args->rpc_ctx->get_response_body());
          CHECK(error["error"]["code"] == ccf::errors::InvalidInput);
        }
        CHECK(fixture.operation->quote_verifications == verified_before);
      }
      else
      {
        CHECK(args->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
        CHECK(fixture.operation->quote_verifications == verified_before + 1);
      }
      CHECK(fixture.read_restarts() == 0);
      CHECK(fixture.environment.events.empty());
    }
  }
}

TEST_CASE("Recovery restart waits for global commit and occurs once")
{
  using State = recovery_decision_protocol::StateMachine;
  RecoveryProtocolFixture fixture;
  const auto before = fixture.network.tables->current_txid_and_commit_term();

  {
    auto aborted = fixture.prepare(
      "recovery_decision_protocol/iamopen", fixture.iamopen_request());
    REQUIRE(aborted->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
    CHECK(fixture.read_restarts() == 0);
    CHECK(fixture.environment.events.empty());

    SUBCASE("Discarded transaction") {}
    SUBCASE("Conflicting transaction")
    {
      auto conflict = fixture.network.tables->create_tx();
      conflict
        .rw<recovery_decision_protocol::TimeoutSMState>(
          Tables::RECOVERY_DECISION_PROTOCOL_TIMEOUT_SM_STATE)
        ->put(State::VOTING);
      REQUIRE(conflict.commit() == ccf::kv::CommitResult::SUCCESS);
      CHECK(
        aborted->owned_tx->commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
    }
    SUBCASE("Locally committed transaction rolled back before global commit")
    {
      REQUIRE(aborted->owned_tx->commit() == ccf::kv::CommitResult::SUCCESS);
      CHECK(fixture.read_restarts() == 0);
      CHECK(fixture.environment.events.empty());
      fixture.network.tables->rollback(before.first, before.second);
    }
  }
  fixture.network.tables->compact(fixture.network.tables->current_version());
  CHECK(fixture.read_restarts() == 0);
  CHECK(fixture.environment.events.empty());
  {
    auto tx = fixture.network.tables->create_read_only_tx();
    CHECK(
      tx.ro<recovery_decision_protocol::SMState>(
          Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
        ->get() == State::GOSSIPING);
  }

  auto accepted = fixture.prepare(
    "recovery_decision_protocol/iamopen", fixture.iamopen_request());
  REQUIRE(accepted->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  REQUIRE(accepted->owned_tx->commit() == ccf::kv::CommitResult::SUCCESS);
  CHECK(fixture.read_restarts() == 0);
  CHECK(fixture.environment.events.empty());
  fixture.network.tables->compact(fixture.network.tables->current_version());
  CHECK(fixture.read_restarts() == 1);
#ifdef CCF_RECOVERY_TRACE
  REQUIRE(fixture.environment.events.size() == 2);
  CHECK(fixture.environment.events[0]["kind"] == "iamopen_accepted");
  CHECK(fixture.environment.events[0]["caused_by"] == "opener:1");
  CHECK(fixture.environment.events[1]["kind"] == "join_restart");
  for (const auto& event : fixture.environment.events)
  {
    CHECK_FALSE(event.contains("version"));
  }
#endif

  fixture.environment.events.clear();
  auto duplicate_request = fixture.iamopen_request();
  duplicate_request.message_id = "opener:2";
  auto duplicate =
    fixture.prepare("recovery_decision_protocol/iamopen", duplicate_request);
  REQUIRE(duplicate->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  REQUIRE(duplicate->owned_tx->commit() == ccf::kv::CommitResult::SUCCESS);
  fixture.network.tables->compact(fixture.network.tables->current_version());
  CHECK(fixture.read_restarts() == 1);
#ifdef CCF_RECOVERY_TRACE
  REQUIRE(fixture.environment.events.size() == 1);
  CHECK(fixture.environment.events[0]["kind"] == "iamopen_accepted");
  CHECK(fixture.environment.events[0]["caused_by"] == "opener:2");
  CHECK(fixture.environment.events[0]["pre"] == "JOINING");
  CHECK(fixture.environment.events[0]["post"] == "JOINING");
#else
  CHECK(fixture.environment.events.empty());
#endif

  fixture.environment.events.clear();
  auto timeout =
    fixture.prepare("recovery_decision_protocol/timeout", json::object());
  REQUIRE(timeout->rpc_ctx->get_response_status() == HTTP_STATUS_OK);
  REQUIRE(timeout->owned_tx->commit() == ccf::kv::CommitResult::SUCCESS);
  CHECK(fixture.read_restarts() == 1);
  CHECK(fixture.environment.events.empty());
  fixture.network.tables->compact(fixture.network.tables->current_version());
  CHECK(fixture.read_restarts() == 1);
#ifdef CCF_RECOVERY_TRACE
  REQUIRE(fixture.environment.events.size() == 1);
  CHECK(fixture.environment.events[0]["kind"] == "timeout");
  CHECK(fixture.environment.events[0]["pre"] == "JOINING");
  CHECK(fixture.environment.events[0]["post"] == "JOINING");
  CHECK_FALSE(fixture.environment.events[0].contains("version"));
#endif
}
