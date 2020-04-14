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

#include "big_req_table.h"
#include "client_proxy.h"
#include "consensus/pbft/pbft_tables.h"
#include "ds/files.h"
#include "ds/thread_messaging.h"
#include "host/ledger.h"
#include "itimer.h"
#include "libbyz.h"
#include "network_impl.h"
#include "nodeinfo.h"
#include "pbft_assert.h"
#include "replica.h"
#include "stacktrace_utils.h"
#include "statistics.h"
#include "test_message.h"
#include "timer.h"

using std::cerr;

static const int Simple_size = 4096;

enclave::ThreadMessaging enclave::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> enclave::ThreadMessaging::thread_count = 0;

static Timer t;
static ITimer* test_timer;
static ITimer* delay_test_timer;
int random_delay_order = 100000;
int test_timer_order = 1000;
bool with_timeouts = false;
bool write_to_ledger = false;
bool have_executed_request = false;
const int max_num_principals = 1000;
int broken_requests[max_num_principals];

static void dump_profile(int sig)
{
  unsigned short buf;
  profil(&buf, 0, 0, 0);

  LOG_INFO << "Printing stats" << std::endl;
  stats.print_stats();

  exit(0);
}

void introduce_random_delay()
{
  if (have_executed_request)
  {
    auto random_delay = random_delay_order * (lrand48() % 100);
    LOG_INFO << "Sleeping for microseconds: " << random_delay << std::endl;

    usleep(random_delay);
    have_executed_request = false;
  }
  else
  {
    LOG_INFO << "Skipping Sleeping " << std::endl;
  }
}

void test_timer_handler(void* owner)
{
  introduce_random_delay();
  test_timer->restart();
}

void delayed_start_delay_time(void* owner)
{
  if ((pbft::GlobalState::get_replica().id() % 2) == 0) // half the nodes
                                                        // including the primary
  {
    auto delay = 10 * 1000 * 1000; // sleep for 10 seconds
    LOG_INFO << "Sleeping for " << (delay / (1000 * 1000))
             << " seconds to force view change" << std::endl;
    usleep(delay);
  }

  auto timeout_time = test_timer_order * ((lrand48() % 100) + 1);
  LOG_INFO << "Init timer with milliseconds " << timeout_time << std::endl;
  test_timer = new ITimer(timeout_time, test_timer_handler, nullptr);
  test_timer->start();
}

void start_delay_timer()
{
  auto delay = 5 * 1000; // sleep in 5 seconds
  if ((pbft::GlobalState::get_replica().id() % 2) == 0) // half the nodes
                                                        // including the primary
  {
    delay += 10 * 1000; // make sure that all the replicas do not sleep when
                        // enforcing the first view change
  }

  delay_test_timer = new ITimer(delay, delayed_start_delay_time, nullptr);
  delay_test_timer->start();
}

static std::unique_ptr<ClientProxy<uint64_t, void>> client_proxy;
static std::unique_ptr<ITimer> send_req_timer;
static const size_t client_proxy_req_size = 8;
static size_t reply_count = 0;
static size_t request_count = 0;
void setup_client_proxy()
{
  LOG_INFO << "Setting up client proxy " << std::endl;
  client_proxy.reset(
    new ClientProxy<uint64_t, void>(pbft::GlobalState::get_replica()));

  auto cb = [](Reply* m, void* ctx) {
    auto cp = (ClientProxy<uint64_t, void>*)ctx;
    cp->recv_reply(m);
  };
  pbft::GlobalState::get_replica().register_reply_handler(
    cb, client_proxy.get());

  auto req_timer_cb = [](void* ctx) {
    auto cp = (ClientProxy<uint64_t, void>*)ctx;

    static const uint32_t max_pending_requests = 7;
    while (request_count - reply_count < max_pending_requests)
    {
      uint8_t request_buffer[8];
      auto request = new (request_buffer) test_req;
      Time t = ITimer::current_time();

      request->option = 0;
      for (size_t j = 0; j < request->get_array_size(client_proxy_req_size);
           j++)
      {
        memcpy(&request->get_counter_array()[j], &t, sizeof(int64_t));
      }

      auto rep_cb = [](
                      void* owner,
                      uint64_t caller_rid,
                      int status,
                      uint8_t* reply,
                      size_t len) {
        reply_count++;

        if (reply_count % 100 == 0)
        {
          LOG_INFO << " Reply count " << reply_count << std::endl;
        }
        return true;
      };

      bool ret = cp->send_request(
        t, request_buffer, sizeof(request_buffer), rep_cb, client_proxy.get());
      if (ret)
      {
        request_count++;
      }
      else
      {
        break;
      }
    }

    send_req_timer->restart();
  };

  send_req_timer.reset(new ITimer(100, req_timer_cb, client_proxy.get()));
  send_req_timer->start();
}

static char* service_mem = 0;
static IMessageReceiveBase* message_receive_base;

ExecCommand exec_command =
  [](
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

      outb.contents =
        message_receive_base->create_response_message(client, rid, 8, nonce);

      Long& counter = *(Long*)service_mem;
      Long* client_counter_arrays = (Long*)service_mem + sizeof(Long);
      auto client_counter = client_counter_arrays[client];

      Byz_modify(&counter, sizeof(counter));
      counter++;
      have_executed_request = true;

      info.replicated_state_merkle_root.fill(0);
      ((Long*)(info.replicated_state_merkle_root.data()))[0] = counter;
      info.ctx = counter;

      if (total_requests_executed != counter)
      {
        LOG_FATAL << "total requests executed: " << total_requests_executed
                  << " not equal to exec command counter: " << counter << "\n";
        throw std::logic_error(
          "Total requests executed not equal to exec command counter");
      }

      if (total_requests_executed % 100 == 0)
      {
        LOG_INFO << "total requests executed " << total_requests_executed
                 << "\n";
      }

      auto request = new (inb->contents) test_req;

      for (size_t j = 0; j < request->get_array_size(inb->size); j++)
      {
        uint64_t request_array_counter;
        memcpy(
          &request_array_counter,
          &request->get_counter_array()[j],
          sizeof(uint64_t));

        if (client_counter != request_array_counter && !broken_requests[client])
        {
          broken_requests[client] = 1;
          LOG_INFO << "client: " << client
                   << " broken state: " << broken_requests[client] << std::endl;
          LOG_INFO << "client: " << client << std::endl;
          LOG_INFO << "client counter: " << client_counter
                   << " is smaller than request counter: "
                   << request_array_counter << "\n";
        }
        else if (
          client_counter == request_array_counter && broken_requests[client])
        {
          LOG_INFO << "client: " << client << std::endl;
          broken_requests[client] = 0;
          LOG_INFO << "client: " << client
                   << " broken state: " << broken_requests[client] << std::endl;
          LOG_INFO << "Fixed c counter: " << client_counter
                   << " is NOT smaller than request counter: "
                   << request_array_counter << "\n";
        }
      }

      Byz_modify(&client_counter_arrays[client], sizeof(Long));
      client_counter_arrays[client] = ++client_counter;

      // A simple service.
      if (request->option == 1)
      {
        PBFT_ASSERT(inb->size == 8, "Invalid request");
        Byz_modify(outb.contents, Simple_size);
        bzero(outb.contents, Simple_size);
        outb.size = Simple_size;
        return 0;
      }

      PBFT_ASSERT(
        (request->option == 2 && inb->size == Simple_size) ||
          (request->option == 0 && inb->size == 8),
        "Invalid request");
      Byz_modify(outb.contents, 8);
      *((long long*)(outb.contents)) = 0;
      outb.size = 8;
      msg->cb(*msg.get(), info);
    }
    return 0;
  };

int main(int argc, char** argv)
{
  CLI::App app{"Run Replica Test"};

  // run tests
  short port = 0;
  app.add_option("--port", port, "Port", true);

  bool print_to_stdout = false;
  app.add_flag("--stdout", print_to_stdout);

  std::string transport_layer = "UDP";
  app.add_option(
    "--transport", transport_layer, "Transport layer [UDP || UDP_MT]");

  app.add_option(
    "--timer-order",
    test_timer_order,
    "Order of magnitued for the test timer timeout intervals");
  app.add_option(
    "--delay-order", random_delay_order, "Order of mangitude of random delay");

  std::string config_file = "config.json";
  app.add_option("--config", config_file, "General config info", true)
    ->check(CLI::ExistingFile);

  NodeId id;
  app.add_option("--id", id, "Nodes id", true);

  std::string privk_file;
  app.add_option("--privk_file", privk_file, "Private key file", true)
    ->check(CLI::ExistingFile);

  app.add_flag("--with-delays", with_timeouts, "Insert delays");

  app.add_flag("--ledger", write_to_ledger, "Should write to ledger");

  bool test_client_proxy = false;
  app.add_flag("--test-client-proxy", test_client_proxy, "Test client proxy");

  CLI11_PARSE(app, argc, argv);

  if (!print_to_stdout)
  {
    logger::Init(std::to_string(port).c_str());
  }

  GeneralInfo general_info = files::slurp_json(config_file);

  general_info.max_requests_between_signatures = 10;

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

  int mem_size = 256;
  char* mem = (char*)valloc(mem_size);
  bzero(mem, mem_size);

  srand48(getpid());

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
  auto& signatures = store->create<ccf::Signatures>(ccf::Tables::SIGNATURES);
  auto replica_store =
    std::make_unique<pbft::Adaptor<ccf::Store, kv::DeserialiseSuccess>>(store);

  int used_bytes = Byz_init_replica(
    node_info,
    mem,
    mem_size,
    exec_command,
    network,
    pbft_requests_map,
    pbft_pre_prepares_map,
    signatures,
    *replica_store,
    &message_receive_base);

  Byz_start_replica();
  service_mem = mem + used_bytes;
  Byz_configure_principals();

  if (with_timeouts)
  {
    start_delay_timer();
  }

  if (test_client_proxy)
  {
    setup_client_proxy();
  }

  Byz_replica_run();
}
