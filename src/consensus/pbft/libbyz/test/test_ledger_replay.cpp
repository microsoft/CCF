// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "consensus/pbft/pbft_pre_prepares.h"
#include "consensus/pbft/pbft_requests.h"
#include "consensus/pbft/pbft_tables.h"
#include "consensus/pbft/pbft_types.h"
#include "consensus/test/stub_consensus.h"
#include "host/ledger.h"
#include "message.h"
#include "network_mock.h"
#include "node.h"
#include "replica.h"
#include "request.h"
#include "tls/key_pair.h"

#include <cstdio>
#include <doctest/doctest.h>

enclave::ThreadMessaging enclave::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> enclave::ThreadMessaging::thread_count = 0;

// power of 2 since ringbuffer circuit size depends on total_requests
static constexpr size_t total_requests = 32;

class ExecutionMock
{
public:
  ExecutionMock(size_t init_counter_) : command_counter(init_counter_) {}
  size_t command_counter;
  struct fake_req
  {
    uint8_t rt;
    int64_t ctx;
  };

  ExecCommand exec_command =
    [this](
      std::array<std::unique_ptr<ExecCommandMsg>, Max_requests_in_batch>& msgs,
      ByzInfo& info,
      uint32_t num_requests,
      uint64_t nonce) {
      for (uint32_t i = 0; i < num_requests; ++i)
      {
        std::unique_ptr<ExecCommandMsg>& msg = msgs[i];
        Byz_req* inb = &msg->inb;
        Byz_rep& outb = msg->outb;
        int client = msg->client;
        Request_id rid = msg->rid;
        uint8_t* req_start = msg->req_start;
        size_t req_size = msg->req_size;
        Seqno total_requests_executed = msg->total_requests_executed;
        ccf::Store::Tx* tx = msg->tx;

        // increase total number of commands executed to compare with fake_req
        command_counter++;

        outb.contents =
          pbft::GlobalState::get_replica().create_response_message(
            client, rid, 0, nonce);
        outb.size = 0;
        auto request = reinterpret_cast<fake_req*>(inb->contents);
        info.ctx = request->ctx;
        info.replicated_state_merkle_root.fill(0);
        info.replicated_state_merkle_root.data()[0] = request->rt;

        REQUIRE(request->rt == command_counter);
        msg->cb(*msg.get(), info);
      }
      return 0;
    };
};

namespace pbft
{
  struct RollbackInfo
  {
    pbft::PbftStore* store;
    size_t* called;
    ExecutionMock* execution_mock;
  } register_rollback_ctx;
}

NodeInfo get_node_info()
{
  auto kp = tls::make_key_pair();
  std::vector<PrincipalInfo> principal_info;

  auto node_cert = kp->self_sign("CN=CCF node");

  PrincipalInfo pi = {0, (short)(3000), "ip", node_cert, "name-1", true};
  principal_info.emplace_back(pi);

  GeneralInfo gi = {false,
                    2,
                    0,
                    0,
                    "generic",
                    1800000,
                    5000,
                    100,
                    9999250000,
                    50,
                    principal_info};

  NodeInfo node_info = {gi.principal_info[0], kp->private_key_pem().str(), gi};

  return node_info;
}

void create_replica(
  std::vector<char>& service_mem,
  pbft::PbftStore& store,
  pbft::RequestsMap& pbft_requests_map,
  pbft::PrePreparesMap& pbft_pre_prepares_map,
  ccf::Signatures& signatures)
{
  auto node_info = get_node_info();

  pbft::GlobalState::set_replica(std::make_unique<Replica>(
    node_info,
    service_mem.data(),
    service_mem.size(),
    Create_Mock_Network(),
    pbft_requests_map,
    pbft_pre_prepares_map,
    signatures,
    store));

  pbft::GlobalState::get_replica().init_state();

  for (auto& pi : node_info.general_info.principal_info)
  {
    if (pi.id != node_info.own_info.id)
    {
      pbft::GlobalState::get_replica().add_principal(pi);
    }
  }
}

Request* create_and_store_request(
  size_t index,
  pbft::PbftStore& store,
  pbft::RequestsMap& req_map,
  ccf::Store::Map<std::string, std::string>* derived_map = nullptr)
{
  Byz_req req;
  Byz_alloc_request(&req, sizeof(ExecutionMock::fake_req));

  auto fr = reinterpret_cast<ExecutionMock::fake_req*>(req.contents);
  fr->rt = index;
  // context would be the version of the executed command
  fr->ctx = store.current_version() + 1;

  Request* request = (Request*)req.opaque;
  request->request_id() = index;
  request->authenticate(req.size, false);

  ccf::Store::Tx tx;
  auto req_view = tx.get_view(req_map);

  int command_size;
  auto command_start = request->command(command_size);

  req_view->put(
    0,
    {0,
     {},
     {command_start, command_start + command_size},
     {(const uint8_t*)request->contents(),
      (const uint8_t*)request->contents() + request->size()}});

  if (derived_map)
  {
    auto der_view = tx.get_view(*derived_map);
    der_view->put("key1", "value1");
  }

  REQUIRE(tx.commit() == kv::CommitSuccess::OK);

  return request;
}

void populate_entries(
  std::vector<std::vector<uint8_t>>& entries,
  std::shared_ptr<kv::StubConsensus> consensus)
{
  while (true)
  {
    auto ret = consensus->pop_oldest_data();
    if (!ret.second)
    {
      break;
    }
    entries.emplace_back(ret.first);
  }
}

TEST_CASE("Test Ledger Replay")
{
  // initiate replica with stub consensus to be used on replay
  auto write_consensus =
    std::make_shared<kv::StubConsensus>(ConsensusType::PBFT);
  INFO("Create dummy pre-prepares and write them to ledger");
  {
    auto write_store = std::make_shared<ccf::Store>(
      pbft::replicate_type_pbft, pbft::replicated_tables_pbft);
    write_store->set_consensus(write_consensus);
    auto& write_pbft_requests_map = write_store->create<pbft::RequestsMap>(
      pbft::Tables::PBFT_REQUESTS, kv::SecurityDomain::PUBLIC);
    auto& signatures =
      write_store->create<ccf::Signatures>(ccf::Tables::SIGNATURES);
    auto& write_pbft_pre_prepares_map =
      write_store->create<pbft::PrePreparesMap>(
        pbft::Tables::PBFT_PRE_PREPARES, kv::SecurityDomain::PUBLIC);
    auto& write_derived_map = write_store->create<std::string, std::string>(
      "derived_map", kv::SecurityDomain::PUBLIC);

    auto write_pbft_store =
      std::make_unique<pbft::Adaptor<ccf::Store, kv::DeserialiseSuccess>>(
        write_store);

    int mem_size = 256;
    std::vector<char> service_mem(mem_size, 0);
    ExecutionMock exec_mock(0);

    create_replica(
      service_mem,
      *write_pbft_store,
      write_pbft_requests_map,
      write_pbft_pre_prepares_map,
      signatures);
    pbft::GlobalState::get_replica().register_exec(exec_mock.exec_command);

    for (size_t i = 1; i < total_requests; i++)
    {
      auto request = create_and_store_request(
        i, *write_pbft_store, write_pbft_requests_map, &write_derived_map);
      // replica handle request (creates and writes pre prepare to ledger)
      pbft::GlobalState::get_replica().handle(request);
    }
    // remove the requests that were not processed, only written to the ledger
    pbft::GlobalState::get_replica().big_reqs()->clear();
  }

  auto corrupt_consensus =
    std::make_shared<kv::StubConsensus>(ConsensusType::PBFT);
  INFO("Create dummy corrupt pre-prepares and write them to ledger");
  {
    // initialise a corrupt store that will follow the write store but with
    // the requests and merkle root off and use it later to trigger rollbacks
    auto corrupt_store = std::make_shared<ccf::Store>(
      pbft::replicate_type_pbft, pbft::replicated_tables_pbft);
    corrupt_store->set_consensus(corrupt_consensus);
    auto& corr_req_map = corrupt_store->create<pbft::RequestsMap>(
      pbft::Tables::PBFT_REQUESTS, kv::SecurityDomain::PUBLIC);
    auto& corr_pp_map = corrupt_store->create<pbft::PrePreparesMap>(
      pbft::Tables::PBFT_PRE_PREPARES, kv::SecurityDomain::PUBLIC);
    auto& signatures =
      corrupt_store->create<ccf::Signatures>(ccf::Tables::SIGNATURES);
    auto corr_pbft_store =
      std::make_unique<pbft::Adaptor<ccf::Store, kv::DeserialiseSuccess>>(
        corrupt_store);

    int mem_size = 256;
    std::vector<char> service_mem(mem_size, 0);
    ExecutionMock exec_mock(0);
    exec_mock.command_counter++;

    create_replica(
      service_mem, *corr_pbft_store, corr_req_map, corr_pp_map, signatures);
    pbft::GlobalState::get_replica().register_exec(exec_mock.exec_command);

    LedgerWriter ledger_writer(*corr_pbft_store, corr_pp_map, signatures);

    Req_queue rqueue;
    for (size_t i = 1; i < total_requests; i++)
    {
      auto request =
        create_and_store_request(i, *corr_pbft_store, corr_req_map);

      // request is compatible but pre-prepare root is different
      rqueue.append(request);
      size_t num_requests = 1;
      auto pp = std::make_unique<Pre_prepare>(1, i, rqueue, num_requests, 0);

      // imitate exec command
      ByzInfo info;
      info.ctx = i;
      info.replicated_state_merkle_root.fill(0);
      // mess up merkle roots
      info.replicated_state_merkle_root.data()[0] = i + 1;

      pp->set_merkle_roots_and_ctx(info.replicated_state_merkle_root, info.ctx);

      ledger_writer.write_pre_prepare(pp.get());
    }
    // remove the requests that were not processed, only written to the ledger
    pbft::GlobalState::get_replica().big_reqs()->clear();
  }

  INFO(
    "Read the ledger entries and replay them out of order, while being "
    "corrupt, and in order");
  {
    auto store = std::make_shared<ccf::Store>(
      pbft::replicate_type_pbft, pbft::replicated_tables_pbft);
    auto consensus = std::make_shared<kv::StubConsensus>(ConsensusType::PBFT);
    store->set_consensus(consensus);
    auto& pbft_requests_map = store->create<pbft::RequestsMap>(
      pbft::Tables::PBFT_REQUESTS, kv::SecurityDomain::PUBLIC);
    auto& pbft_pre_prepares_map = store->create<pbft::PrePreparesMap>(
      pbft::Tables::PBFT_PRE_PREPARES, kv::SecurityDomain::PUBLIC);
    auto& signatures = store->create<ccf::Signatures>(ccf::Tables::SIGNATURES);
    auto& derived_map = store->create<std::string, std::string>(
      "derived_map", kv::SecurityDomain::PUBLIC);

    auto replica_store =
      std::make_unique<pbft::Adaptor<ccf::Store, kv::DeserialiseSuccess>>(
        store);

    int mem_size = 256;
    std::vector<char> service_mem(mem_size, 0);
    ExecutionMock exec_mock(0);

    create_replica(
      service_mem,
      *replica_store,
      pbft_requests_map,
      pbft_pre_prepares_map,
      signatures);
    pbft::GlobalState::get_replica().register_exec(exec_mock.exec_command);

    // create rollback cb
    size_t call_rollback = 0;
    kv::Version rb_version;

    auto rollback_cb =
      [](kv::Version version, pbft::RollbackInfo* rollback_info) {
        (*rollback_info->called)++;
        rollback_info->store->rollback(version);
        rollback_info->execution_mock->command_counter--;
      };

    pbft::register_rollback_ctx.called = &call_rollback;
    pbft::register_rollback_ctx.store = replica_store.get();
    pbft::register_rollback_ctx.execution_mock = &exec_mock;

    pbft::GlobalState::get_replica().register_rollback_cb(
      rollback_cb, &pbft::register_rollback_ctx);

    // ledgerenclave work
    std::vector<std::vector<uint8_t>> entries;
    std::vector<std::vector<uint8_t>> corrupt_entries;
    populate_entries(entries, write_consensus);
    populate_entries(corrupt_entries, corrupt_consensus);

    // apply out of order first
    REQUIRE(
      store->deserialise(entries.back()) == kv::DeserialiseSuccess::FAILED);

    ccf::Store::Tx tx;
    auto req_view = tx.get_view(pbft_requests_map);
    auto req = req_view->get(0);
    REQUIRE(!req.has_value());

    auto pp_view = tx.get_view(pbft_pre_prepares_map);
    auto pp = pp_view->get(0);
    REQUIRE(!pp.has_value());

    REQUIRE(entries.size() > 0);

    Seqno seqno = 1;
    size_t iterations = 0;
    size_t count_rollbacks = 0;
    // keep latest executed request so that we can re-apply it after a rollback
    std::vector<uint8_t> lastest_executed_request;
    // apply all of the data in order
    for (size_t i = 0; i < entries.size(); i++)
    {
      const auto& entry = entries.at(i);
      const auto& corrupt_entry = corrupt_entries.at(i);

      if (iterations % 2)
      {
        // odd entries are pre prepares
        // try to deserialise corrupt pre-prepare which should trigger a
        // rollback
        ccf::Store::Tx tx;
        REQUIRE(
          store->deserialise_views(corrupt_entry, false, nullptr, &tx) ==
          kv::DeserialiseSuccess::PASS_PRE_PREPARE);
        REQUIRE_THROWS_AS(
          pbft::GlobalState::get_replica().playback_pre_prepare(tx),
          std::logic_error);
        count_rollbacks++;

        // rolled back latest request so need to re-execute
        ccf::Store::Tx re_exec_tx;
        REQUIRE(
          store->deserialise_views(
            lastest_executed_request, false, nullptr, &re_exec_tx) ==
          kv::DeserialiseSuccess::PASS);
        pbft::GlobalState::get_replica().playback_request(re_exec_tx);
        REQUIRE(re_exec_tx.commit() == kv::CommitSuccess::OK);
      }

      if (iterations % 2)
      {
        // odd entries are pre prepares
        ccf::Store::Tx tx;
        REQUIRE(
          store->deserialise_views(entry, false, nullptr, &tx) ==
          kv::DeserialiseSuccess::PASS_PRE_PREPARE);
        pbft::GlobalState::get_replica().playback_pre_prepare(tx);

        ccf::Store::Tx read_tx;
        auto pp_view = read_tx.get_view(pbft_pre_prepares_map);
        auto pp = pp_view->get(0);
        REQUIRE(pp.has_value());
        REQUIRE(pp.value().seqno == seqno);
        seqno++;
      }
      else
      {
        // even entries are requests
        ccf::Store::Tx tx;
        REQUIRE(
          store->deserialise_views(entry, false, nullptr, &tx) ==
          kv::DeserialiseSuccess::PASS);
        pbft::GlobalState::get_replica().playback_request(tx);
        // pre-prepares are committed in playback_pre_prepare
        REQUIRE(tx.commit() == kv::CommitSuccess::OK);

        ccf::Store::Tx read_tx;
        lastest_executed_request = entry;
        // even entries are requests
        auto req_view = read_tx.get_view(pbft_requests_map);
        auto req = req_view->get(0);
        REQUIRE(req.has_value());
        REQUIRE(req.value().raw.size() > 0);
      }

      // no derived data should have gotten deserialised
      ccf::Store::Tx read_tx;
      auto der_view = read_tx.get_view(derived_map);
      auto derived_val = der_view->get("key1");
      REQUIRE(!derived_val.has_value());

      iterations++;
    }

    auto last_executed = pbft::GlobalState::get_replica().get_last_executed();
    REQUIRE(last_executed == total_requests - 1);
    REQUIRE(call_rollback == count_rollbacks);
  }
}