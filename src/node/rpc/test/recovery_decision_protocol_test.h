// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "frontend_test_infra.h"
#include "kv/test/null_encryptor.h"
#include "node/recovery_decision_protocol.h"
#include "node_stub.h"
#include "service/tables/previous_service_identity.h"
#include "tasks/task_system.h"

namespace ccf::recovery_decision_protocol::test
{
  // The frontend harness disables doctest's exception assertions.
  template <typename F>
  void check_logic_error(F&& operation, const std::string& expected)
  {
    bool caught = false;
    try
    {
      operation();
    }
    catch (const std::logic_error& e)
    {
      caught = true;
      CHECK(std::string(e.what()) == expected);
    }
    CHECK(caught);
  }

  struct Node : public AbstractRecoveryDecisionProtocolNode
  {
    RequestNodeInfo info;
    TxID recovered_txid = {2, 42};
    size_t cache_calls = 0;
    size_t restarts = 0;

    NodeId get_node_id() const override
    {
      return NodeId{"test-node"};
    }

    void cache_node_info(
      std::optional<RequestNodeInfo>& cache,
      const QuoteInfo& quote_info) override
    {
      ++cache_calls;
      cache = info;
      cache->quote_info = quote_info;
    }

    crypto::Pem get_self_signed_certificate() override
    {
      throw std::logic_error("Unexpected network request");
    }

    crypto::Pem get_private_key() override
    {
      throw std::logic_error("Unexpected network request");
    }

    TxID get_last_recovered_signed_txid() override
    {
      return recovered_txid;
    }

    void restart() override
    {
      ++restarts;
    }
  };

  struct Governance : public StubGovernanceEffects
  {
    size_t opens = 0;
    kv::Tx* expected_tx = nullptr;
    bool fail = false;

    void transition_service_to_open(
      kv::Tx& tx, ServiceIdentities identities) override
    {
      ++opens;
      CHECK(&tx == expected_tx);
      CHECK(
        tx.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)->get() ==
        StateMachine::OPENING);
      auto* service = tx.rw<Service>(Tables::SERVICE);
      auto info = service->get().value();
      CHECK(identities.next == info.cert);
      CHECK(
        identities.previous ==
        tx.ro<PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
          ->get());
      info.status = ServiceStatus::OPEN;
      service->put(info);
      if (fail)
      {
        throw std::logic_error("Rejected recovery transition");
      }
    }
  };

  struct Fixture
  {
    std::optional<SealingRecoveryConfig> config;
    std::shared_ptr<kv::Store> tables;
    Governance governance;
    Node node;
    RecoveryDecisionProtocolSubsystem protocol{
      config, tables, governance, node};

    Fixture()
    {
      tables = std::make_shared<kv::Store>();
      tables->set_encryptor(std::make_shared<kv::NullTxEncryptor>());
      config = SealingRecoveryConfig{
        .location = {"a", "localhost:1234"},
        .recovery_decision_protocol = RecoveryDecisionProtocolConfig{
          .expected_locations =
            {{"a", "localhost:1234"},
             {"b", "localhost:1235"},
             {"c", "localhost:1236"}},
          .failover_timeout = {"0ms"}}};
    }

    void set_state(kv::Tx& tx, StateMachine state)
    {
      tx.rw<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)->put(state);
      tx.rw<TimeoutSMState>(Tables::RECOVERY_DECISION_PROTOCOL_TIMEOUT_SM_STATE)
        ->put(state);
    }
  };

  TEST_CASE(
    "Recovery protocol start gates and global commit" *
    doctest::test_suite("recovery_decision_protocol"))
  {
    Fixture f;
    auto& board = tasks::get_main_job_board();
    REQUIRE(board.get_summary().pending_tasks == 0);

    {
      auto tx = f.tables->create_tx();
      f.protocol.try_start(tx, false);
      CHECK_FALSE(tx.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
                    ->get()
                    .has_value());
      f.config.reset();
      f.protocol.try_start(tx, true);
      CHECK_FALSE(tx.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
                    ->get()
                    .has_value());
      f.config.emplace();
      f.protocol.try_start(tx, true);
      CHECK_FALSE(tx.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
                    ->get()
                    .has_value());
      f.config->recovery_decision_protocol.emplace();
      f.config->recovery_decision_protocol->failover_timeout = {"0ms"};
      f.protocol.try_start(tx, true);
      tasks::tick(std::chrono::milliseconds(0));
      CHECK(board.get_summary().pending_tasks == 0);
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }
    tasks::tick(std::chrono::milliseconds(0));
    CHECK(board.get_summary().pending_tasks == 0);
    f.tables->rollback({0, 0}, 1);
    f.tables->compact(0);
    tasks::tick(std::chrono::milliseconds(0));
    CHECK(board.get_summary().pending_tasks == 0);

    {
      auto tx = f.tables->create_tx();
      f.protocol.try_start(tx, true);
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }
    f.tables->compact(f.tables->current_version());
    tasks::tick(std::chrono::milliseconds(0));
    auto retry = board.get_task();
    REQUIRE(retry != nullptr);
    struct CancelTask
    {
      tasks::Task task;
      ~CancelTask()
      {
        task->cancel_task();
      }
    } cancel{retry};
    CHECK(retry->get_name() == "RecoveryDecisionProtocolRetry");
    CHECK(board.get_summary().pending_tasks == 0);

    // Callback-time reads must use the live store slot, not a constructor copy.
    f.tables = std::make_shared<kv::Store>();
    f.tables->set_encryptor(std::make_shared<kv::NullTxEncryptor>());
    {
      auto tx = f.tables->create_tx();
      f.set_state(tx, StateMachine::OPEN);
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }
    retry->do_task();
    CHECK(retry->is_cancelled());
    tasks::tick(std::chrono::milliseconds(100));
    CHECK(board.get_summary().pending_tasks == 0);
  }

  TEST_CASE(
    "Recovery protocol governance uses the caller transaction" *
    doctest::test_suite("recovery_decision_protocol"))
  {
    Fixture f;
    auto identity = make_test_network_ident();
    bool timeout = false;
    size_t votes = 2;
    SUBCASE("Quorum") {}
    SUBCASE("Failover")
    {
      timeout = true;
      votes = 1;
    }
    SUBCASE("No votes")
    {
      timeout = true;
      votes = 0;
    }
    SUBCASE("Governance failure")
    {
      f.governance.fail = true;
    }
    {
      auto tx = f.tables->create_tx();
      f.set_state(tx, StateMachine::VOTING);
      tx.rw<Service>(Tables::SERVICE)
        ->put(ServiceInfo{identity->cert, ServiceStatus::RECOVERING});
      tx.rw<PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
        ->put(identity->cert);
      for (size_t i = 0; i < votes; ++i)
      {
        tx.rw<Votes>(Tables::RECOVERY_DECISION_PROTOCOL_VOTES)
          ->insert(std::to_string(i));
      }
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }
    {
      auto tx = f.tables->create_tx();
      f.governance.expected_tx = &tx;
      if (f.governance.fail)
      {
        check_logic_error(
          [&]() { f.protocol.advance(tx, timeout); },
          "Rejected recovery transition");
      }
      else
      {
        f.protocol.advance(tx, timeout);
        REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
      }
    }
    auto tx = f.tables->create_read_only_tx();
    const auto opened = votes > 0 && !f.governance.fail;
    CHECK(f.governance.opens == (votes > 0 ? 1 : 0));
    CHECK(
      tx.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)->get() ==
      (opened ? StateMachine::OPENING : StateMachine::VOTING));
    CHECK(
      tx.ro<Service>(Tables::SERVICE)->get()->status ==
      (opened ? ServiceStatus::OPEN : ServiceStatus::RECOVERING));
    auto kind =
      tx.ro<OpenKind>(Tables::RECOVERY_DECISION_PROTOCOL_OPEN_KIND)->get();
    if (opened)
    {
      CHECK(kind == (timeout ? OpenKinds::FAILOVER : OpenKinds::QUORUM));
    }
    else
    {
      CHECK_FALSE(kind.has_value());
    }
  }

  TEST_CASE(
    "Recovery protocol node info cache and missing state" *
    doctest::test_suite("recovery_decision_protocol"))
  {
    Fixture f;
    auto identity = make_test_network_ident();
    f.node.info.location = f.config->location;
    f.node.info.service_cert_der = crypto::cert_pem_to_der(identity->cert);
    auto tx = f.tables->create_tx();
    check_logic_error(
      [&]() { f.protocol.get_iamopen_request(tx); },
      "Previous service identity not found in table but expected as "
      "recovering");
    tx.rw<PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
      ->put(identity->cert);
    check_logic_error(
      [&]() { f.protocol.get_iamopen_request(tx); },
      "Node n[test-node] not found in nodes table");
    ccf::NodeInfo node_info;
    node_info.encryption_pub_key = dummy_enc_pubk;
    tx.rw<Nodes>(Tables::NODES)->put(f.node.get_node_id(), node_info);
    auto first = f.protocol.get_iamopen_request(tx);
    CHECK(first.txid == f.node.recovered_txid);
    CHECK(first.info.location == f.config->location);
    CHECK(first.info.service_cert_der == f.node.info.service_cert_der);
    CHECK(
      first.prev_service_fingerprint ==
      service_fingerprint_from_pem(identity->cert));
    f.node.recovered_txid = {3, 50};
    auto second = f.protocol.get_iamopen_request(tx);
    CHECK(second.txid == first.txid);
    CHECK(f.node.cache_calls == 1);
  }

  TEST_CASE(
    "Recovery protocol restart requires a chosen node" *
    doctest::test_suite("recovery_decision_protocol"))
  {
    Fixture f;
    auto tx = f.tables->create_tx();
    f.set_state(tx, StateMachine::JOINING);
    check_logic_error(
      [&]() { f.protocol.advance(tx, false); },
      "Recovery-decision-protocol chosen node not set, cannot join");
    tx.rw<ChosenNode>(Tables::RECOVERY_DECISION_PROTOCOL_CHOSEN_NODE)->put("b");
    check_logic_error(
      [&]() { f.protocol.advance(tx, false); },
      "Recovery-decision-protocol chosen node b not found");
    CHECK(f.node.restarts == 0);
    auto identity = make_test_network_ident();
    NodeInfo chosen{
      {.quote_info = {},
       .location = {"b", "localhost:1235"},
       .service_cert_der = crypto::cert_pem_to_der(identity->cert)},
      {}};
    tx.rw<NodeInfoMap>(Tables::RECOVERY_DECISION_PROTOCOL_NODES)
      ->put("b", chosen);
    f.protocol.advance(tx, false);
    CHECK(f.node.restarts == 1);
    CHECK(
      tx.ro<SMState>(Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)->get() ==
      StateMachine::JOINING);
  }
}
