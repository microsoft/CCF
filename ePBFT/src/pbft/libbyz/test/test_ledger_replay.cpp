// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "Message.h"
#include "Node.h"
#include "Replica.h"
#include "Request.h"
#include "host/ledger.h"
#include "network_mock.h"

#include <cstdio>
#include <doctest/doctest.h>

static constexpr size_t TOTAL_REQUESTS = 1050;

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

  ExecCommand exec_command = [](
                               Byz_req* inb,
                               Byz_rep* outb,
                               _Byz_buffer* non_det,
                               int client,
                               bool ro,
                               Seqno total_requests_executed,
                               ByzInfo& info) {
    auto request = reinterpret_cast<fake_req*>(inb->contents);
    info.ctx = request->ctx;
    info.merkle_root.fill(0);
    info.merkle_root.data()[0] = request->rt;
    return 0;
  };
};

NodeInfo get_node_info()
{
  std::vector<PrincipalInfo> principal_info;

  PrincipalInfo pi = {
    0,
    (short)(3000),
    "ip",
    "96031a6cbe405894f1c0295881bd3946f0215f95fc40b7f1f0cc89b821c58504",
    "8691c3438859c142a26b5f251b96f39a463799430315d34ce8a4db0d2638f751",
    "name-1",
    true};
  principal_info.emplace_back(pi);

  GeneralInfo gi = {
    2, 0, 0, true, "generic", 1800000, 5000, 100, 9999250000, principal_info};

  NodeInfo node_info = {
    gi.principal_info[0],
    "0045c65ec31179652c57ae97f50de77e177a939dce74e39d7db51740663afb69",
    gi};

  return node_info;
}

void init_replica(std::vector<char>& service_mem)
{
  auto node_info = get_node_info();
  replica = new Replica(
    node_info, service_mem.data(), service_mem.size(), Create_Mock_Network());
  replica->init_state();
  for (auto& pi : node_info.general_info.principal_info)
  {
    if (pi.id != node_info.own_info.id)
    {
      replica->add_principal(pi);
    }
  }
}

TEST_CASE("Test Ledger Replay")
{
  ringbuffer::Circuit eio(2);
  auto wf = ringbuffer::WriterFactory(eio);

  std::string initial_ledger = "initial.ledger";
  std::string replay_ledger = "replay.ledger";
  std::remove(initial_ledger.c_str());
  std::remove(replay_ledger.c_str());

  int mem_size = 400 * 8192;
  std::vector<char> service_mem(mem_size, 0);
  ExecutionMock exec_mock(0);
  init_replica(service_mem);
  replica->register_exec(exec_mock.exec_command);

  INFO("Create dummy pre-prepares and write them to ledger file");
  {
    auto initial_ledger_io =
      std::make_unique<asynchost::Ledger>(initial_ledger, wf);

    auto append_ledger_entry_cb =
      [](const uint8_t* data, size_t size, void* ctx) {
        auto ledger = static_cast<asynchost::Ledger*>(ctx);
        ledger->write_entry(data, size);
      };

    LedgerWriter ledger_writer(append_ledger_entry_cb, initial_ledger_io.get());

    Req_queue rqueue;
    for (size_t i = 1; i < TOTAL_REQUESTS; i++)
    {
      Byz_req req;
      Byz_alloc_request(&req, sizeof(ExecutionMock::fake_req));

      auto fr = reinterpret_cast<ExecutionMock::fake_req*>(req.contents);
      fr->rt = i;
      fr->ctx = i;

      Request* request = (Request*)req.opaque;
      request->request_id() = i;
      request->authenticate(req.size, false);
      request->mark_verified();
      request->trim();

      rqueue.append(request);
      size_t num_requests = 1;
      auto pp = std::make_unique<Pre_prepare>(1, i, rqueue, num_requests);

      // imitate exec command
      ByzInfo info;
      info.ctx = fr->ctx;
      info.merkle_root.fill(0);
      info.merkle_root.data()[0] = fr->rt;

      pp->set_merkle_root_and_ctx(info.merkle_root, info.ctx);

      ledger_writer.write_pre_prepare(pp.get());
    }
    // remove the requests that were not processed, only written to the ledger
    replica->big_reqs()->clear();
  }

  INFO("Read the ledger file and replay it out of order and in order");
  {
    auto replay_ledger_io =
      std::make_unique<asynchost::Ledger>(replay_ledger, wf);

    auto append_ledger_entry_cb =
      [](const uint8_t* data, size_t size, void* ctx) {
        auto ledger = static_cast<asynchost::Ledger*>(ctx);
        ledger->write_entry(data, size);
      };

    replica->register_append_ledger_entry_cb(
      append_ledger_entry_cb, replay_ledger_io.get());

    auto initial_ledger_io =
      std::make_unique<asynchost::Ledger>(initial_ledger, wf);

    // check that nothing gets executed out of order

    auto resp = initial_ledger_io->read_framed_entries(5, 9);
    CHECK(!replica->apply_ledger_data(resp));

    resp = initial_ledger_io->read_framed_entries(1, 3);
    CHECK(replica->apply_ledger_data(resp));

    resp = initial_ledger_io->read_framed_entries(1, 3);
    CHECK(!replica->apply_ledger_data(resp));

    resp = initial_ledger_io->read_framed_entries(2, 3);
    CHECK(!replica->apply_ledger_data(resp));

    // execute the rest of the pre-prepares in batches of 4
    for (size_t i = 4; i < TOTAL_REQUESTS; i += 4)
    {
      auto until = std::min(TOTAL_REQUESTS - 1, i + 3);
      resp = initial_ledger_io->read_framed_entries(i, until);
      CHECK(replica->apply_ledger_data(resp));
    }
  }

  INFO("Check that the two ledger files are identical");
  FILE* file1;
  file1 = fopen(initial_ledger.c_str(), "r");
  REQUIRE(file1 != nullptr);
  fseeko(file1, 0, SEEK_END);
  auto file_size1 = ftello(file1);
  REQUIRE(file_size1 != 1);
  fseeko(file1, 0, SEEK_SET);

  FILE* file2;
  file2 = fopen(replay_ledger.c_str(), "r");
  REQUIRE(file2 != nullptr);
  fseeko(file2, 0, SEEK_END);
  auto file_size2 = ftello(file2);
  REQUIRE(file_size2 != 1);
  fseeko(file2, 0, SEEK_SET);

  CHECK(file_size1 == file_size2);

  std::vector<uint8_t> file1_data(file_size1);
  std::vector<uint8_t> file2_data(file_size2);

  CHECK(fread(file1_data.data(), file_size1, 1, file1) == 1);
  CHECK(fread(file2_data.data(), file_size2, 1, file2) == 1);

  CHECK(memcmp(file1_data.data(), file2_data.data(), file_size1));
}