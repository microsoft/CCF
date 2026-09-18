// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/verifier.h"
#include "ds/internal_logger.h"
#include "ds/ring_buffer.h"
#include "kv/test/null_encryptor.h"
#ifdef CCF_RECOVERY_TRACE
#  include "node/commit_callback_interface.h"
#endif
#include "node/node_state.h"
#include "node/rpc/node_frontend.h"
#include "node/rpc_context_impl.h"
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

#ifdef CCF_RECOVERY_TRACE
  class RecoveryTestCommitCallbacks : public CommitCallbackInterface
  {
    struct PendingCallback
    {
      ccf::TxID txid;
      ccf::CommitCallback callback;
    };

    std::vector<PendingCallback> callbacks;

  public:
    bool fail_registration = false;

    void add_callback(ccf::TxID txid, ccf::CommitCallback&& callback) override
    {
      if (fail_registration)
      {
        throw std::logic_error("Trace callback registration failed");
      }
      callbacks.push_back({txid, std::move(callback)});
    }

    size_t size() const
    {
      return callbacks.size();
    }

    void resolve(const ccf::TxID& txid, ccf::FinalTxStatus status)
    {
      const auto it = std::find_if(
        callbacks.begin(), callbacks.end(), [&](const auto& entry) {
          return entry.txid == txid;
        });
      if (it == callbacks.end())
      {
        throw std::logic_error(
          fmt::format("No commit callback registered for {}", txid.to_str()));
      }

      auto callback = std::move(it->callback);
      callbacks.erase(it);
      callback(txid, status);
    }
  };
#endif

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
#ifdef CCF_RECOVERY_TRACE
    std::shared_ptr<RecoveryTestCommitCallbacks> commit_callbacks =
      std::make_shared<RecoveryTestCommitCallbacks>();
#endif
    std::shared_ptr<RecoveryTestFrontend> frontend;
    size_t restart_count = 0;

    RecoveryProtocolFixture()
    {
      context.install_subsystem(operation);
#ifdef CCF_RECOVERY_TRACE
      context.install_subsystem(commit_callbacks);
#endif
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

    std::unique_ptr<EndpointContextImpl> retry(EndpointContextImpl& previous)
    {
      auto* rpc_ctx =
        dynamic_cast<ccf::RpcContextImpl*>(previous.rpc_ctx.get());
      REQUIRE(rpc_ctx != nullptr);
      rpc_ctx->reset_response();

      auto args = std::make_unique<EndpointContextImpl>(
        previous.rpc_ctx, network.tables->create_tx_ptr());
      auto caller = std::make_unique<NodeCertAuthnIdentity>();
      caller->node_id = ccf::kv::test::PrimaryNodeId;
      args->caller = std::move(caller);
      auto& registry = frontend->get_node_endpoints();
      auto endpoint = registry.find_endpoint(args->tx, *previous.rpc_ctx);
      REQUIRE(endpoint != nullptr);
      registry.execute_endpoint(endpoint, *args);
      return args;
    }

    ccf::TxID locally_commit(EndpointContextImpl& args)
    {
      auto& registry = frontend->get_node_endpoints();
      auto endpoint = registry.find_endpoint(args.tx, *args.rpc_ctx);
      REQUIRE(endpoint != nullptr);
      REQUIRE(args.owned_tx->commit() == ccf::kv::CommitResult::SUCCESS);
      const auto txid = args.owned_tx->get_txid();
      REQUIRE(txid.has_value());
      registry.execute_endpoint_locally_committed(endpoint, args, txid.value());
      return txid.value();
    }

#ifdef CCF_RECOVERY_TRACE
    void resolve(const ccf::TxID& txid, ccf::FinalTxStatus status)
    {
      commit_callbacks->resolve(txid, status);
    }
#endif

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
#ifdef CCF_RECOVERY_TRACE
      if (std::string_view(id).empty())
      {
        CHECK(fixture.environment.events.empty());
      }
      else
      {
        REQUIRE_FALSE(fixture.environment.events.empty());
        CHECK(fixture.environment.events.front()["kind"] == kind + "_accepted");
        CHECK(fixture.environment.events.front().contains("attempt"));
        if (kind == "iamopen")
        {
          REQUIRE(fixture.environment.events.size() == 2);
          CHECK(fixture.environment.events.back()["kind"] == "join_restart");
          CHECK(
            fixture.environment.events.back()["attempt"] ==
            fixture.environment.events.front()["attempt"]);
        }
        else
        {
          CHECK(fixture.environment.events.size() == 1);
        }
      }
#else
      CHECK(fixture.environment.events.empty());
#endif
      fixture.environment.events.clear();
    }
  }
}

TEST_CASE("Recovery attempts are resolved without changing restart behaviour")
{
  using State = recovery_decision_protocol::StateMachine;
  RecoveryProtocolFixture fixture;
  const auto before = fixture.network.tables->current_txid_and_commit_term();
  size_t events_before_accepted = 0;

  {
    auto incomplete = fixture.prepare(
      "recovery_decision_protocol/iamopen", fixture.iamopen_request());
    REQUIRE(
      incomplete->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
    CHECK(fixture.read_restarts() == 0);
#ifdef CCF_RECOVERY_TRACE
    REQUIRE(fixture.environment.events.size() == 2);
    CHECK(fixture.environment.events[0]["kind"] == "iamopen_accepted");
    CHECK(fixture.environment.events[1]["kind"] == "join_restart");
    CHECK(
      fixture.environment.events[0]["attempt"] ==
      fixture.environment.events[1]["attempt"]);
    events_before_accepted = 2;
#else
    CHECK(fixture.environment.events.empty());
#endif

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
        incomplete->owned_tx->commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
    }
    SUBCASE("Locally committed transaction rolled back before global commit")
    {
      [[maybe_unused]] const auto txid = fixture.locally_commit(*incomplete);
      CHECK(fixture.read_restarts() == 0);
#ifdef CCF_RECOVERY_TRACE
      CHECK(fixture.commit_callbacks->size() == 1);
      REQUIRE(fixture.environment.events.size() == events_before_accepted + 1);
      CHECK(fixture.environment.events.back()["kind"] == "locally_committed");
      CHECK(
        fixture.environment.events.back()["attempt"] ==
        fixture.environment.events.front()["attempt"]);
      CHECK(fixture.environment.events.back()["view"] == txid.view);
      CHECK(fixture.environment.events.back()["seqno"] == txid.seqno);
#endif
      fixture.network.tables->rollback(before.first, before.second);
#ifdef CCF_RECOVERY_TRACE
      fixture.resolve(txid, ccf::FinalTxStatus::Invalid);
      REQUIRE(fixture.environment.events.size() == events_before_accepted + 2);
      CHECK(fixture.environment.events.back()["kind"] == "rolled_back");
      CHECK(
        fixture.environment.events.back()["attempt"] ==
        fixture.environment.events.front()["attempt"]);
      CHECK(fixture.environment.events.back()["view"] == txid.view);
      CHECK(fixture.environment.events.back()["seqno"] == txid.seqno);
      events_before_accepted += 2;
#else
      CHECK(fixture.environment.events.empty());
#endif
    }
  }
  fixture.network.tables->compact(fixture.network.tables->current_version());
  CHECK(fixture.read_restarts() == 0);
  CHECK(fixture.environment.events.size() == events_before_accepted);
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
  [[maybe_unused]] const auto accepted_txid = fixture.locally_commit(*accepted);
  CHECK(fixture.read_restarts() == 0);
#ifdef CCF_RECOVERY_TRACE
  REQUIRE(fixture.environment.events.size() == events_before_accepted + 3);
  CHECK(fixture.commit_callbacks->size() == 1);
  CHECK(
    fixture.environment.events[events_before_accepted + 2]["kind"] ==
    "locally_committed");
#else
  CHECK(fixture.environment.events.empty());
#endif
  fixture.network.tables->compact(fixture.network.tables->current_version());
  CHECK(fixture.read_restarts() == 1);
#ifdef CCF_RECOVERY_TRACE
  fixture.resolve(accepted_txid, ccf::FinalTxStatus::Committed);
  REQUIRE(fixture.environment.events.size() == events_before_accepted + 4);
  const auto accepted_event = events_before_accepted;
  CHECK(
    fixture.environment.events[accepted_event]["kind"] == "iamopen_accepted");
  CHECK(fixture.environment.events[accepted_event]["caused_by"] == "opener:1");
  CHECK(
    fixture.environment.events[accepted_event + 1]["kind"] == "join_restart");
  CHECK(
    fixture.environment.events[accepted_event + 3]["kind"] ==
    "globally_committed");
  CHECK(
    fixture.environment.events[accepted_event + 3]["attempt"] ==
    fixture.environment.events[accepted_event]["attempt"]);
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
  [[maybe_unused]] const auto duplicate_txid =
    fixture.locally_commit(*duplicate);
  fixture.network.tables->compact(fixture.network.tables->current_version());
  CHECK(fixture.read_restarts() == 1);
#ifdef CCF_RECOVERY_TRACE
  fixture.resolve(duplicate_txid, ccf::FinalTxStatus::Committed);
  REQUIRE(fixture.environment.events.size() == 3);
  CHECK(fixture.environment.events[0]["kind"] == "iamopen_accepted");
  CHECK(fixture.environment.events[0]["caused_by"] == "opener:2");
  CHECK(fixture.environment.events[0]["pre"] == "JOINING");
  CHECK(fixture.environment.events[0]["post"] == "JOINING");
  CHECK(fixture.environment.events[1]["kind"] == "locally_committed");
  CHECK(fixture.environment.events[2]["kind"] == "globally_committed");
  CHECK(
    fixture.environment.events[2]["attempt"] ==
    fixture.environment.events[0]["attempt"]);
#else
  CHECK(fixture.environment.events.empty());
#endif

  fixture.environment.events.clear();
  auto timeout =
    fixture.prepare("recovery_decision_protocol/timeout", json::object());
  REQUIRE(timeout->rpc_ctx->get_response_status() == HTTP_STATUS_OK);
  [[maybe_unused]] const auto timeout_txid = fixture.locally_commit(*timeout);
  CHECK(fixture.read_restarts() == 1);
  fixture.network.tables->compact(fixture.network.tables->current_version());
  CHECK(fixture.read_restarts() == 1);
#ifdef CCF_RECOVERY_TRACE
  fixture.resolve(timeout_txid, ccf::FinalTxStatus::Committed);
  REQUIRE(fixture.environment.events.size() == 3);
  CHECK(fixture.environment.events[0]["kind"] == "timeout");
  CHECK(fixture.environment.events[0]["pre"] == "JOINING");
  CHECK(fixture.environment.events[0]["post"] == "JOINING");
  CHECK_FALSE(fixture.environment.events[0].contains("version"));
  CHECK(fixture.environment.events[1]["kind"] == "locally_committed");
  CHECK(fixture.environment.events[2]["kind"] == "globally_committed");
  CHECK(
    fixture.environment.events[2]["attempt"] ==
    fixture.environment.events[0]["attempt"]);
#else
  CHECK(fixture.environment.events.empty());
#endif
}

TEST_CASE("Recovery tracing does not add KV writes")
{
  RecoveryProtocolFixture fixture;
  auto gossip = fixture.iamopen_request();
  const auto gossip_json = json(recovery_decision_protocol::GossipRequest{
    {.info = gossip.info, .message_id = "opener:1"}, gossip.txid});

  auto initial =
    fixture.prepare("recovery_decision_protocol/gossip", gossip_json);
  REQUIRE(initial->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  [[maybe_unused]] const auto initial_txid = fixture.locally_commit(*initial);
  fixture.network.tables->compact(fixture.network.tables->current_version());
#ifdef CCF_RECOVERY_TRACE
  fixture.resolve(initial_txid, ccf::FinalTxStatus::Committed);
#endif
  fixture.environment.events.clear();

  auto duplicate_json = gossip_json;
  duplicate_json["message_id"] = "opener:2";
  const auto version_before = fixture.network.tables->current_version();
  auto duplicate =
    fixture.prepare("recovery_decision_protocol/gossip", duplicate_json);
  REQUIRE(duplicate->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  const auto duplicate_txid = fixture.locally_commit(*duplicate);

  CHECK(fixture.network.tables->current_version() == version_before);
  CHECK(duplicate_txid.seqno == version_before);
#ifdef CCF_RECOVERY_TRACE
  fixture.resolve(duplicate_txid, ccf::FinalTxStatus::Committed);
  REQUIRE(fixture.environment.events.size() == 3);
  CHECK(fixture.environment.events[0]["kind"] == "gossip_accepted");
  CHECK(fixture.environment.events[1]["kind"] == "locally_committed");
  CHECK(fixture.environment.events[2]["kind"] == "globally_committed");
#else
  CHECK(fixture.environment.events.empty());
#endif
}

TEST_CASE("Recovery retries supersede incomplete attempts")
{
  RecoveryProtocolFixture fixture;
  const auto iamopen = fixture.iamopen_request();
  recovery_decision_protocol::GossipRequest gossip;
  gossip.info = iamopen.info;
  gossip.txid = iamopen.txid;
  gossip.message_id = "opener:1";

  auto first =
    fixture.prepare("recovery_decision_protocol/gossip", json(gossip));
  REQUIRE(first->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);

  auto conflict = fixture.network.tables->create_tx();
  conflict
    .rw<recovery_decision_protocol::Gossips>(
      Tables::RECOVERY_DECISION_PROTOCOL_GOSSIPS)
    ->put(gossip.info.location.name, gossip.txid);
  REQUIRE(conflict.commit() == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(first->owned_tx->commit() == ccf::kv::CommitResult::FAIL_CONFLICT);

  auto retry = fixture.retry(*first);
  REQUIRE(retry->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  [[maybe_unused]] const auto retry_txid = fixture.locally_commit(*retry);
  fixture.network.tables->compact(fixture.network.tables->current_version());
  CHECK(fixture.read_restarts() == 0);

#ifdef CCF_RECOVERY_TRACE
  fixture.resolve(retry_txid, ccf::FinalTxStatus::Committed);
  REQUIRE(fixture.environment.events.size() == 5);
  CHECK(fixture.environment.events[0]["kind"] == "gossip_accepted");
  CHECK(fixture.environment.events[1]["kind"] == "aborted");
  CHECK(
    fixture.environment.events[1]["attempt"] ==
    fixture.environment.events[0]["attempt"]);
  CHECK(fixture.environment.events[2]["kind"] == "gossip_accepted");
  CHECK(
    fixture.environment.events[2]["attempt"] !=
    fixture.environment.events[0]["attempt"]);
  CHECK(fixture.environment.events[3]["kind"] == "locally_committed");
  CHECK(fixture.environment.events[4]["kind"] == "globally_committed");
  CHECK(
    fixture.environment.events[4]["attempt"] ==
    fixture.environment.events[2]["attempt"]);
#else
  CHECK(fixture.environment.events.empty());
#endif
}

#ifdef CCF_RECOVERY_TRACE
TEST_CASE("Trace callback failures do not fail recovery requests")
{
  RecoveryProtocolFixture fixture;
  fixture.commit_callbacks->fail_registration = true;
  auto request = fixture.prepare(
    "recovery_decision_protocol/iamopen", fixture.iamopen_request());
  REQUIRE(request->rpc_ctx->get_response_status() == HTTP_STATUS_NO_CONTENT);
  CHECK_NOTHROW(fixture.locally_commit(*request));
  CHECK(fixture.commit_callbacks->size() == 0);
  REQUIRE(fixture.environment.events.size() == 3);
  CHECK(fixture.environment.events.back()["kind"] == "locally_committed");
}
#endif
