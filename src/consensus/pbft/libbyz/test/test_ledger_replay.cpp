// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "Message.h"
#include "Node.h"
#include "Replica.h"
#include "Request.h"
#include "consensus/pbft/pbftpreprepares.h"
#include "consensus/pbft/pbftrequests.h"
#include "consensus/pbft/pbfttables.h"
#include "consensus/pbft/pbfttypes.h"
#include "host/ledger.h"
#include "kv/test/stub_consensus.h"
#include "network_mock.h"
#include "tls/keypair.h"

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

  ExecCommand exec_command = [this](
                               Byz_req* inb,
                               Byz_rep& outb,
                               _Byz_buffer* non_det,
                               int client,
                               Request_id rid,
                               bool ro,
                               Seqno total_requests_executed,
                               ByzInfo& info) {
    // increase total number of commands executed to compare with fake_req
    command_counter++;

    outb.contents =
      pbft::GlobalState::get_replica().create_response_message(client, rid, 0);
    outb.size = 0;
    auto request = reinterpret_cast<fake_req*>(inb->contents);
    info.ctx = request->ctx;
    info.full_state_merkle_root.fill(0);
    info.replicated_state_merkle_root.fill(0);
    info.full_state_merkle_root.data()[0] = request->rt;
    info.replicated_state_merkle_root.data()[0] = request->rt;

    REQUIRE(request->ctx == command_counter);
    REQUIRE(request->rt == command_counter);
    return 0;
  };
};

NodeInfo get_node_info()
{
  auto kp = tls::make_key_pair();
  std::vector<PrincipalInfo> principal_info;

  auto node_cert = kp->self_sign("CN=CCF node");

  PrincipalInfo pi = {0, (short)(3000), "ip", node_cert, "name-1", true};
  principal_info.emplace_back(pi);

  GeneralInfo gi = {
    2, 0, 0, "generic", 1800000, 5000, 100, 9999250000, 50, principal_info};

  NodeInfo node_info = {gi.principal_info[0], kp->private_key_pem().str(), gi};

  return node_info;
}

void create_replica(
  std::vector<char>& service_mem,
  pbft::Store& store,
  pbft::RequestsMap& pbft_requests_map,
  pbft::PrePreparesMap& pbft_pre_prepares_map)
{
  auto node_info = get_node_info();

  pbft::GlobalState::set_replica(std::make_unique<Replica>(
    node_info,
    service_mem.data(),
    service_mem.size(),
    Create_Mock_Network(),
    pbft_requests_map,
    pbft_pre_prepares_map,
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

TEST_CASE("Test Ledger Replay")
{
  // initiate replica with stub consensus to be used on replay
  auto write_consensus = std::make_shared<kv::StubConsensus>();
  INFO("Create dummy pre-prepares and write them to ledger");
  {
    auto write_store = std::make_shared<ccf::Store>(
      pbft::replicate_type_pbft, pbft::replicated_tables_pbft);
    write_store->set_consensus(write_consensus);
    auto& write_pbft_requests_map = write_store->create<pbft::RequestsMap>(
      pbft::Tables::PBFT_REQUESTS, kv::SecurityDomain::PUBLIC);
    auto& write_pbft_pre_prepares_map =
      write_store->create<pbft::PrePreparesMap>(
        pbft::Tables::PBFT_PRE_PREPARES, kv::SecurityDomain::PUBLIC);
    auto& write_derived_map = write_store->create<std::string, std::string>(
      "derived_map", kv::SecurityDomain::PUBLIC);

    auto write_pbft_store =
      std::make_unique<pbft::Adaptor<ccf::Store>>(write_store);

    int mem_size = 400 * 8192;
    std::vector<char> service_mem(mem_size, 0);
    ExecutionMock exec_mock(0);

    create_replica(
      service_mem,
      *write_pbft_store,
      write_pbft_requests_map,
      write_pbft_pre_prepares_map);
    pbft::GlobalState::get_replica().register_exec(exec_mock.exec_command);

    Req_queue rqueue;
    for (size_t i = 1; i < total_requests; i++)
    {
      Byz_req req;
      Byz_alloc_request(&req, sizeof(ExecutionMock::fake_req));

      auto fr = reinterpret_cast<ExecutionMock::fake_req*>(req.contents);
      fr->rt = i;
      fr->ctx = i;

      Request* request = (Request*)req.opaque;
      request->request_id() = i;
      request->authenticate(req.size, false);
      request->trim();

      ccf::Store::Tx tx;
      auto req_view = tx.get_view(write_pbft_requests_map);
      req_view->put(
        0,
        {0,
         0,
         {},
         {(const uint8_t*)request->contents(),
          (const uint8_t*)request->contents() + request->size()}});

      auto der_view = tx.get_view(write_derived_map);
      der_view->put("key1", "value1");

      REQUIRE(tx.commit() == kv::CommitSuccess::OK);

      // replica handle request (creates and writes pre prepare to ledger)
      pbft::GlobalState::get_replica().handle(request);
    }
    // remove the requests that were not processed, only written to the ledger
    pbft::GlobalState::get_replica().big_reqs()->clear();
  }

  INFO("Read the ledger entries and replay them out of order and in order");
  {
    auto store = std::make_shared<ccf::Store>(
      pbft::replicate_type_pbft, pbft::replicated_tables_pbft);
    auto consensus = std::make_shared<kv::StubConsensus>();
    store->set_consensus(consensus);
    auto& pbft_requests_map = store->create<pbft::RequestsMap>(
      pbft::Tables::PBFT_REQUESTS, kv::SecurityDomain::PUBLIC);
    auto& pbft_pre_prepares_map = store->create<pbft::PrePreparesMap>(
      pbft::Tables::PBFT_PRE_PREPARES, kv::SecurityDomain::PUBLIC);
    auto& derived_map = store->create<std::string, std::string>(
      "derived_map", kv::SecurityDomain::PUBLIC);
    auto replica_store = std::make_unique<pbft::Adaptor<ccf::Store>>(store);

    int mem_size = 400 * 8192;
    std::vector<char> service_mem(mem_size, 0);
    ExecutionMock exec_mock(0);

    create_replica(
      service_mem, *replica_store, pbft_requests_map, pbft_pre_prepares_map);
    pbft::GlobalState::get_replica().register_exec(exec_mock.exec_command);
    pbft::GlobalState::get_replica().activate_pbft_local_hooks();
    // ledgerenclave work
    std::vector<std::vector<uint8_t>> entries;
    while (true)
    {
      auto ret = write_consensus->pop_oldest_data();
      if (!ret.second)
      {
        break;
      }
      // TODO: when deserialise will be called by pbft, in that place pbft will
      // have to also append the write set to the ledger
      entries.emplace_back(ret.first);
    }
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
    // apply all of the data in order
    for (const auto& entry : entries)
    {
      REQUIRE(store->deserialise(entry) == kv::DeserialiseSuccess::PASS);
      ccf::Store::Tx tx;
      if (iterations % 2)
      {
        // odd entries are pre prepares
        auto pp_view = tx.get_view(pbft_pre_prepares_map);
        auto pp = pp_view->get(0);
        REQUIRE(pp.has_value());
        REQUIRE(pp.value().seqno == seqno);
        seqno++;
      }
      else
      {
        // even entries are requests
        auto req_view = tx.get_view(pbft_requests_map);
        auto req = req_view->get(0);
        REQUIRE(req.has_value());
        REQUIRE(req.value().raw.size() > 0);
      }
      // no derived data should have gotten deserialised
      auto der_view = tx.get_view(derived_map);
      auto derived_val = der_view->get("key1");
      REQUIRE(!derived_val.has_value());

      iterations++;
    }

    auto last_executed = pbft::GlobalState::get_replica().get_last_executed();
    REQUIRE(last_executed == total_requests - 1);
  }
}