// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include <CLI11/CLI11.hpp>
#include <iostream>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

#include "Replica.h"
#include "Statistics.h"
#include "Timer.h"
#include "consensus/pbft/pbfttables.h"
#include "ds/files.h"
#include "libbyz.h"
#include "network_impl.h"
#include "nodeinfo.h"
#include "pbft_assert.h"
#include "stacktrace_utils.h"

using std::cerr;

static const int Simple_size = 4096;

static int start_exec_count =
  20 * 1000 * 1000; // how many ops to run tests for before timing
static int max_exec_count =
  40 * 1000 * 1000; // how many ops to run tests for with timing
static Timer t;

static bool is_test = false;
static IMessageReceiveBase* message_receiver = nullptr;

static void dump_profile(int sig)
{
  unsigned short buf;
  profil(&buf, 0, 0, 0);

  LOG_INFO << "Printing stats" << std::endl;
  stats.print_stats();

  exit(0);
}

static char* service_mem = 0;

// Service specific functions.
ExecCommand exec_command = [](
                             Byz_req* inb,
                             Byz_rep& outb,
                             _Byz_buffer* non_det,
                             int client,
                             Request_id rid,
                             bool ro,
                             Seqno n,
                             ByzInfo& info) {
  outb.contents = message_receiver->create_response_message(client, rid, 8);

  Long& counter = *(Long*)service_mem;

  Byz_modify(&counter, sizeof(counter));
  counter++;

  info.full_state_merkle_root.fill(0);
  ((Long*)(info.full_state_merkle_root.data()))[0] = counter;
  info.replicated_state_merkle_root.fill(0);
  ((Long*)(info.replicated_state_merkle_root.data()))[0] = counter;

  if (!ro & is_test)
  {
    assert(n == counter);
  }

  LOG_DEBUG << "exec_command" << std::endl;
  if (counter == start_exec_count)
  {
    LOG_INFO << "starting timing at " << start_exec_count << " ops\n";
    t.start();
  }
  else if (counter == max_exec_count + start_exec_count)
  {
    LOG_INFO << "stopping execution at " << counter << " ops\n";
    std::cout << "stopping execution at " << counter << " ops\n";
    t.stop();
    LOG_INFO << "Throughput: " << (max_exec_count) / t.elapsed() << "\n";
    std::cout << "Throughput: " << (max_exec_count) / t.elapsed() << "\n";
    dump_profile(0);
  }

  // A simple service.
  if (inb->contents[0] == 1)
  {
    PBFT_ASSERT(inb->size == 8, "Invalid request");
    Byz_modify(outb.contents, Simple_size);
    bzero(outb.contents, Simple_size);
    outb.size = Simple_size;
    return 0;
  }

  PBFT_ASSERT(
    (inb->contents[0] == 2 && inb->size == Simple_size) ||
      (inb->contents[0] == 0 && inb->size == 8),
    "Invalid request");
  Byz_modify(outb.contents, 8);
  *((long long*)(outb.contents)) = 0;
  outb.size = 8;
  return 0;
};

int main(int argc, char** argv)
{
  CLI::App app{"Run Replica Main"};

  // run tests
  short port = 0;
  app.add_option("--port", port, "Port", true);

  bool print_to_stdout = false;
  app.add_flag("--stdout", print_to_stdout);

  std::string transport_layer = "UDP";
  app.add_option(
    "--transport", transport_layer, "Transport layer [UDP || UDP_MT]");

  std::string config_file = "config.json";
  app.add_option("--config", config_file, "General config info", true)
    ->check(CLI::ExistingFile);

  NodeId id;
  app.add_option("--id", id, "Nodes id", true);

  std::string privk_file;
  app.add_option("--privk_file", privk_file, "Private key file", true)
    ->check(CLI::ExistingFile);

  CLI11_PARSE(app, argc, argv);

  if (!print_to_stdout)
  {
    logger::Init(std::to_string(port).c_str());
  }

  GeneralInfo general_info = files::slurp_json(config_file);
  // as to not add double escapes on newline when slurping from file
  PrivateKey privk_j = files::slurp_json(privk_file);
  NodeInfo node_info;
  tls::KeyPairPtr kp = tls::make_key_pair(privk_j.privk);
  auto node_cert = kp->self_sign("CN=CCF node");

  for (auto& pi : general_info.principal_info)
  {
    pi.cert = node_cert;
  }

  for (auto& pi : general_info.principal_info)
  {
    if (pi.id == id)
    {
      node_info = {pi, privk_j.privk, general_info};
      break;
    }
  }

  LOG_INFO << "Printing command line arguments" << std::endl;
  std::stringstream cmd_line;
  for (int i = 0; i < argc; ++i)
  {
    cmd_line << argv[i] << " ";
  }
  LOG_INFO << cmd_line.str() << std::endl;

  LOG_INFO << "Starting replica main" << std::endl;

  EverCrypt_AutoConfig2_init();

  // signal handler to dump profile information.
  struct sigaction act;
  act.sa_handler = dump_profile;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  sigaction(SIGINT, &act, NULL);
  sigaction(SIGTERM, &act, NULL);

  int mem_size = 550 * 8192;
  char* mem = (char*)valloc(mem_size);
  bzero(mem, mem_size);

  INetwork* network = nullptr;
  if (transport_layer == "UDP")
  {
    network = Create_UDP_Network().release();
    LOG_INFO << "Transport: UDP" << std::endl;
  }
  else if (transport_layer == "UDP_MT")
  {
    network =
      Create_UDP_Network_MultiThreaded(id % num_receivers_replicas).release();
    LOG_INFO << "Transport: UDP_MT" << std::endl;
  }
  else
  {
    LOG_FATAL << "--transport {UDP || UDP_MT}" << std::endl;
  }

  auto store = std::make_shared<ccf::Store>(
    pbft::replicate_type_pbft, pbft::replicated_tables_pbft);
  auto& pbft_requests_map = store->create<pbft::RequestsMap>(
    pbft::Tables::PBFT_REQUESTS, kv::SecurityDomain::PUBLIC);
  auto& pbft_pre_prepares_map = store->create<pbft::PrePreparesMap>(
    pbft::Tables::PBFT_PRE_PREPARES, kv::SecurityDomain::PUBLIC);
  auto replica_store = std::make_unique<pbft::Adaptor<ccf::Store>>(store);

  int used_bytes = Byz_init_replica(
    node_info,
    mem,
    mem_size,
    exec_command,
    0,
    0,
    network,
    pbft_requests_map,
    pbft_pre_prepares_map,
    *replica_store,
    &message_receiver);

  Byz_start_replica();
  service_mem = mem + used_bytes;
  Byz_configure_principals();

  stats.zero_stats();

  // Loop executing requests.
  Byz_replica_run();
}
