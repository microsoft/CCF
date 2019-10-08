// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once
#include "LedgerReader.h"
#include "Message.h"
#include "Node.h"
#include "Replica.h"
#include "Request.h"
#include "network_mock_tcp.h"

struct fake_req
{
  size_t counter;
};

ExecCommand exec_command = [](
                             Byz_req* inb,
                             Byz_rep* outb,
                             _Byz_buffer* non_det,
                             int client,
                             bool ro,
                             Seqno total_requests_executed,
                             ByzInfo& info) { return 0; };

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
    1, 0, 0, true, "generic", 1800000, 5000, 100, 9999250000, principal_info};

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
    node_info,
    service_mem.data(),
    service_mem.size(),
    Create_Mock_TCP_Network());
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
  int mem_size = 400 * 8192;
  std::string initial_ledger = "initial.ledger";
  std::string replay_ledger = "replay.ledger";
  {
    std::vector<char> service_mem(mem_size, 0);
    init_replica(service_mem);
    // Create ledger
    auto ledger_ofs = std::make_unique<std::ofstream>();

    std::string ledger_name(initial_ledger);

    ledger_ofs->open(
      ledger_name.c_str(), std::ofstream::out | std::ofstream::trunc);

    auto append_ledger_entry_cb =
      [](const uint8_t* data, size_t size, void* ctx) {
        std::ofstream* ledger_ofs = static_cast<std::ofstream*>(ctx);
        ledger_ofs->write((const char*)data, size);
        ledger_ofs->flush();
      };

    LedgerWriter ledger_writer(append_ledger_entry_cb, ledger_ofs.get());

    for (int i = 0; i < 10; i += 2)
    {
      Req_queue rqueue;
      Byz_req req;
      Byz_alloc_request(&req, sizeof(fake_req));

      auto fr = reinterpret_cast<fake_req*>(req.contents);
      fr->counter = 5;

      Request* request = (Request*)req.opaque;
      request->request_id() = i;
      request->authenticate(req.size, false);
      request->mark_verified();
      request->trim();
      rqueue.append(request);
      size_t num_requests = 1;
      auto pp = std::make_unique<Pre_prepare>(1, i, rqueue, num_requests);
      ledger_writer.write_pre_prepare(pp.get());
    }
    delete replica;
  }

  // Replay ledger
  {
    std::vector<char> service_mem(mem_size, 0);
    init_replica(service_mem);

    auto ledger_ofs = std::make_unique<std::ofstream>();

    std::string ledger_name(replay_ledger);

    ledger_ofs->open(
      ledger_name.c_str(), std::ofstream::out | std::ofstream::trunc);

    auto append_ledger_entry_cb =
      [](const uint8_t* data, size_t size, void* ctx) {
        std::ofstream* ledger_ofs = static_cast<std::ofstream*>(ctx);
        ledger_ofs->write((const char*)data, size);
        ledger_ofs->flush();
      };

    LedgerWriter ledger_writer(append_ledger_entry_cb, ledger_ofs.get());
    LedgerReplay ledger_replay(0);
    LedgerReader ledger_reader(initial_ledger);

    Req_queue rqueue;

    while (true)
    {
      auto ledger_position = ledger_replay.cursor();

      auto entry = ledger_reader.read_next_entry(ledger_position);
      if (entry.empty())
      {
        break;
      }

      ledger_replay.apply_data(
        entry, rqueue, *replica->big_reqs(), &ledger_writer);
    }

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

    delete replica;
  }
}
