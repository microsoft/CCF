// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/jwt_key_auto_refresh.h"

#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace std::chrono_literals;

namespace
{
  class RefreshEndpoint : public ccf::RpcHandler
  {
  public:
    bool accept_keys = true;
    size_t key_updates = 0;

    void set_sig_intervals(size_t, size_t) override {}
    void set_cmd_forwarder(std::shared_ptr<ccf::AbstractForwarder>) override {}
    void open() override {}
    bool is_open() override
    {
      return true;
    }
    void set_consensus_and_history(
      ccf::kv::Consensus*, ccf::kv::TxHistory*) override
    {}

    void process(std::shared_ptr<ccf::RpcContextImpl> ctx) override
    {
      const auto body = ccf::parse_json_safe(ctx->get_request_body());
      if (body.is_object())
      {
        ++key_updates;
      }
      ctx->set_response_status(
        body.is_object() && accept_keys ? HTTP_STATUS_OK :
                                          HTTP_STATUS_INTERNAL_SERVER_ERROR);
    }
  };

  struct Fixture
  {
    ccf::NetworkState network;
    std::shared_ptr<ccf::kv::test::StubConsensus> consensus =
      std::make_shared<ccf::kv::test::StubConsensus>();
    std::shared_ptr<RefreshEndpoint> endpoint =
      std::make_shared<RefreshEndpoint>();
    std::shared_ptr<ccf::JwtKeyAutoRefresh> refresh;
    const ccf::JwtIssuer issuer = "https://issuer.example";

    Fixture(size_t refresh_interval_s = 30)
    {
      network.tables->set_encryptor(
        std::make_shared<ccf::kv::NullTxEncryptor>());
      consensus->force_become_primary();
      auto rpc_map = std::make_shared<ccf::RPCMap>();
      rpc_map->register_frontend<ccf::ActorsType::nodes>(endpoint);
      refresh = std::make_shared<ccf::JwtKeyAutoRefresh>(
        refresh_interval_s,
        network,
        consensus,
        rpc_map,
        nullptr,
        ccf::crypto::Pem{},
        4096);
      set_issuer(issuer);
    }

    ~Fixture()
    {
      refresh.reset();
      advance(1h);
    }

    void set_issuer(const ccf::JwtIssuer& name, bool auto_refresh = true)
    {
      auto tx = network.tables->create_tx();
      // A missing CA bundle makes each attempt fail synchronously, without
      // wall-clock waits or external HTTP servers.
      tx.rw(network.jwt_issuers)
        ->put(name, ccf::JwtIssuerMetadata{std::nullopt, auto_refresh});
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    void advance(std::chrono::milliseconds elapsed)
    {
      ccf::tasks::tick(elapsed);
      auto& job_board = ccf::tasks::get_main_job_board();
      while (auto task = job_board.get_task())
      {
        task->do_task();
      }
    }

    void expect_retry_after(std::chrono::milliseconds delay)
    {
      const auto attempts = refresh->get_attempts();
      advance(delay - 1ms);
      REQUIRE(refresh->get_attempts() == attempts);
      advance(1ms);
      REQUIRE(refresh->get_attempts() == attempts + 1);
    }

    void respond_with_keys(const ccf::JwtIssuer& name)
    {
      const auto body = nlohmann::json(ccf::JsonWebKeySet{}).dump();
      refresh->handle_jwt_jwks_response(
        name,
        std::nullopt,
        HTTP_STATUS_OK,
        std::vector<uint8_t>(body.begin(), body.end()));
    }

    std::shared_ptr<ccf::tasks::BasicTask> take_ready_retry()
    {
      auto task = std::dynamic_pointer_cast<ccf::tasks::BasicTask>(
        ccf::tasks::get_main_job_board().get_task());
      REQUIRE(task != nullptr);
      return task;
    }
  };
}

TEST_CASE("JWT retries double their delay up to the configured maximum")
{
  Fixture f;
  f.refresh->refresh_jwt_keys(f.issuer);
  REQUIRE(f.refresh->get_attempts() == 1);
  for (const auto delay : {5s, 10s, 20s, 30s, 30s})
  {
    f.expect_retry_after(delay);
  }
}

TEST_CASE("JWT retries respect a maximum below the initial retry delay")
{
  Fixture f(3);
  f.refresh->refresh_jwt_keys(f.issuer);
  f.expect_retry_after(3s);
  f.expect_retry_after(3s);
}

TEST_CASE("JWT refresh failures do not replace or advance a pending retry")
{
  Fixture f;
  f.refresh->refresh_jwt_keys(f.issuer);
  f.advance(2s);
  f.refresh->refresh_jwt_keys(f.issuer);
  REQUIRE(f.refresh->get_attempts() == 2);
  f.expect_retry_after(3s);
  f.expect_retry_after(10s);
}

TEST_CASE("JWT retry backoff and successful resets are independent per issuer")
{
  Fixture f;
  const ccf::JwtIssuer other = "https://other.example";
  f.set_issuer(other);
  f.refresh->refresh_jwt_keys(f.issuer);
  f.expect_retry_after(5s);

  f.refresh->refresh_jwt_keys(other);
  f.expect_retry_after(5s);
  f.respond_with_keys(other);
  REQUIRE(f.endpoint->key_updates == 1);

  f.expect_retry_after(5s);
  f.refresh->refresh_jwt_keys(other);
  f.expect_retry_after(5s);
  f.respond_with_keys(other);
  f.expect_retry_after(15s);
}

TEST_CASE("JWT retries reset only after the keys are accepted")
{
  Fixture f;
  f.refresh->refresh_jwt_keys(f.issuer);
  f.expect_retry_after(5s);

  f.endpoint->accept_keys = false;
  f.respond_with_keys(f.issuer);
  f.expect_retry_after(10s);

  f.endpoint->accept_keys = true;
  f.respond_with_keys(f.issuer);
  REQUIRE(f.endpoint->key_updates == 2);
  const auto attempts = f.refresh->get_attempts();
  f.advance(30s);
  REQUIRE(f.refresh->get_attempts() == attempts);

  f.refresh->refresh_jwt_keys(f.issuer);
  f.expect_retry_after(5s);
}

TEST_CASE("Stale JWT retry callbacks cannot consume a newer retry")
{
  Fixture f;
  f.refresh->refresh_jwt_keys(f.issuer);
  ccf::tasks::tick(5s);
  auto stale = f.take_ready_retry();

  SUBCASE("A completed callback is invoked again")
  {
    stale->do_task();
    REQUIRE(f.refresh->get_attempts() == 2);
  }
  SUBCASE("Success cancels the callback and a later failure recreates state")
  {
    f.respond_with_keys(f.issuer);
    REQUIRE(stale->is_cancelled());
    f.refresh->refresh_jwt_keys(f.issuer);
  }

  const auto attempts = f.refresh->get_attempts();
  // Invoke the callback directly to model a worker that has already passed
  // BaseTask's cancellation check before the newer retry was scheduled.
  stale->fn();
  REQUIRE(f.refresh->get_attempts() == attempts);
  f.expect_retry_after(stale->is_cancelled() ? 5s : 10s);
}

TEST_CASE("JWT retries stop when the issuer or primary role is lost")
{
  Fixture f;
  f.refresh->refresh_jwt_keys(f.issuer);

  SUBCASE("Issuer removed")
  {
    auto tx = f.network.tables->create_tx();
    tx.rw(f.network.jwt_issuers)->remove(f.issuer);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  SUBCASE("Auto-refresh disabled")
  {
    f.set_issuer(f.issuer, false);
  }
  SUBCASE("Node is no longer primary")
  {
    f.consensus->state = ccf::kv::test::StubConsensus::Backup;
  }

  f.advance(5s);
  f.advance(30s);
  REQUIRE(f.refresh->get_attempts() == 1);

  f.set_issuer(f.issuer);
  f.consensus->force_become_primary();
  f.refresh->refresh_jwt_keys(f.issuer);
  f.expect_retry_after(5s);
}

TEST_CASE("Stopping JWT refresh cancels callbacks and prevents new retries")
{
  Fixture f;
  f.refresh->refresh_jwt_keys(f.issuer);
  ccf::tasks::tick(5s);
  auto retry = f.take_ready_retry();
  f.refresh->stop();
  REQUIRE(retry->is_cancelled());
  retry->fn();
  f.refresh->send_refresh_jwt_keys_error(f.issuer);
  f.advance(30s);
  REQUIRE(f.refresh->get_attempts() == 1);
}
