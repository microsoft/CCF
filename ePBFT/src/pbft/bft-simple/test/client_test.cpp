// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include <CLI11/CLI11.hpp>
#include <chrono>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

#include "Statistics.h"
#include "Timer.h"
#include "ds/files.h"
#include "libbyz.h"
#include "network_impl.h"
#include "nodeinfo.h"
#include "pbft_assert.h"
#include "stacktrace_utils.h"
#include "test_message.h"

static const int Simple_size = 4096;

enum class MeasureState : int
{
  warmup = 0,
  measure,
  cooldown,
  end
};

static void dump_stats(int sig)
{
  LOG_INFO << "Printing stats" << std::endl;
  stats.print_stats();

  exit(0);
}

int main(int argc, char** argv)
{
  bool read_only = false;

  CLI::App app{"Run Client Test"};

  short port = 0;
  app.add_option("--port", port, "Port", true);

  bool print_to_stdout = false;
  app.add_flag("--stdout", print_to_stdout);

  std::string transport_layer = "UDP";
  app.add_option(
    "--transport",
    transport_layer,
    "Transport layer [UDP || TCP_ZMQ || UDP_MT]");

  int num_iter = 1000;
  app.add_option("--iterations", num_iter, "Number of iterations");

  int option = 0; // null command
  bool read = false;
  app.add_flag("--read", read, "Command to run is the read command");

  bool write = false;
  app.add_flag("--write", write, "Command to run is the write command");

  uint32_t warmup_ms = 10 * 1000;
  app.add_option("--warmup", warmup_ms, "Warm up in milliseconds");

  uint32_t measure_ms = 30 * 1000;
  app.add_option("--measure", measure_ms, "Measure time in milliseconds");

  uint32_t cooldown_ms = 10 * 1000;
  app.add_option("--cooldown", cooldown_ms, "Cool down in milliseconds");

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

  if (read)
  {
    option = 1;
  }

  if (write)
  {
    option = 2;
  }

  GeneralInfo general_info = files::slurp_json(config_file);
  std::string privk = files::slurp_string(privk_file);
  NodeInfo node_info;
  for (auto& pi : general_info.principal_info)
  {
    if (pi.id == id)
    {
      node_info = {pi, privk, general_info};
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

  EverCrypt_AutoConfig2_init();

  INetwork* network = nullptr;
  if (transport_layer == "TCP_ZMQ")
  {
    network = Create_ZMQ_TCP_Network().release();
    LOG_INFO << "Transport: TCP_ZMQ" << std::endl;
  }
  else if (transport_layer == "UDP")
  {
    network = Create_UDP_Network().release();
    LOG_INFO << "Transport: UDP" << std::endl;
  }
  else if (transport_layer == "UDP_MT")
  {
    // we are not using multi-threaded UDP at the client
    network =
      Create_UDP_Network(num_receivers_replicas + id % num_receivers_clients)
        .release();
    LOG_INFO << "Transport: UDP_MT" << std::endl;
  }
  else
  {
    LOG_FATAL << "--transport {UDP || TCP_ZMQ || UDP_MT}" << std::endl;
  }

  // signal handler to dump stats.
  struct sigaction act;
  act.sa_handler = dump_stats;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  sigaction(SIGINT, &act, NULL);
  sigaction(SIGTERM, &act, NULL);

  // Initialize client
  Byz_init_client(node_info, network);
  Byz_configure_principals();

  //
  // Loop invoking requests:
  //

  // Allocate request
  Byz_req req;
  Byz_alloc_request(&req, Simple_size);
  PBFT_ASSERT(Simple_size <= req.size, "Request too big");

  // Store data into request
  for (int i = 0; i < Simple_size; i++)
  {
    req.contents[i] = option;
  }

  if (option != 2)
  {
    req.size = 8;
  }
  else
  {
    req.size = Simple_size;
  }
  auto request = new (req.contents) test_req;

  stats.zero_stats();

  LOG_INFO << "Starting client, iters=" << num_iter << std::endl;

  Byz_rep rep;
  size_t i = 0;
  while (1)
  {
    request->option = option;
    for (size_t j = 0; j < request->get_array_size(req.size); j++)
    {
      memcpy(&request->get_counter_array()[j], &i, sizeof(int64_t));
    }

    Byz_invoke(&req, &rep, read_only);

    // Check reply
    PBFT_ASSERT(
      ((option == 2 || option == 0) && rep.size == 8) ||
        (option == 1 && rep.size == Simple_size),
      "Invalid reply");

    // Free reply
    Byz_free_reply(&rep);

    if (i % 100 == 0)
    {
      LOG_INFO << "i, " << i << " operations complete\n" << std::endl;
    }
    i++;
  }

  Byz_free_request(&req);
}
