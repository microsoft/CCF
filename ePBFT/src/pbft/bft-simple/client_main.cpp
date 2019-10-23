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
#include "ds/file.h"
#include "libbyz.h"
#include "network_impl.h"
#include "nodeinfo.h"
#include "pbft_assert.h"
#include "simple.h"
#include "stacktrace_utils.h"

enum class MeasureState : int
{
  warmup = 0,
  measure,
  cooldown,
  end
};

int main(int argc, char** argv)
{
  bool read_only = false;

  CLI::App app{"Run Client Main"};

  short port = 0;
  app.add_option("--port", port, "Port", true);

  bool print_to_stdout = false;
  app.add_flag("--stdout", print_to_stdout);

  std::string transport_layer = "UDP";
  app.add_option(
    "--transport", transport_layer, "Transport layer [UDP || UDP_MT]");

  int num_iter = 1000;
  app.add_option("--iterations", num_iter, "Number of iterations");

  int option = 0; // null command
  bool read = false;
  app.add_flag("--read", read, "Command to run is the read command");
  if (read)
  {
    option = 1;
  }

  bool write = false;
  app.add_flag("--write", write, "Command to run is the write command");
  if (write)
  {
    option = 2;
  }

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
  if (transport_layer == "UDP")
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
    LOG_FATAL << "--transport {UDP || UDP_MT}" << std::endl;
  }

  srand48(getpid());

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

  stats.zero_stats();

  LOG_INFO << "Starting client, iters=" << num_iter << std::endl;

  typedef std::chrono::high_resolution_clock Clock;
  auto begin = Clock::now();
  MeasureState state = MeasureState::warmup;
  std::vector<std::vector<std::chrono::milliseconds>> request_latency_histogram;
  request_latency_histogram.resize(
    (warmup_ms + measure_ms + cooldown_ms) / 1000);

  for (auto& v : request_latency_histogram)
  {
    v.reserve(10 * 1000);
  }

  uint64_t start_op_id;
  uint64_t end_op_id;

  Timer t;
  Byz_rep rep;
  for (int i = 0; state != MeasureState::end; i++)
  {
    // Invoke request

    auto now = Clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - begin)
                .count();
    switch (state)
    {
      case MeasureState::warmup:
        if (state != MeasureState::measure && ms > warmup_ms)
        {
          LOG_INFO << "starting to measure " << ms << "ms" << std::endl;
          start_op_id = i;
          state = MeasureState::measure;
          t.start();
        }
        break;

      case MeasureState::measure:
        if (state != MeasureState::cooldown && ms > (warmup_ms + measure_ms))
        {
          end_op_id = i;
          LOG_INFO << "ending measure " << ms << "ms" << std::endl;
          state = MeasureState::cooldown;
          t.stop();
        }
        break;

      case MeasureState::cooldown:
        if (
          state != MeasureState::end &&
          ms > (warmup_ms + measure_ms + cooldown_ms))
        {
          state = MeasureState::end;
        }
        break;

      default:
        LOG_FATAL << "Unknown state: " << (int)state << std::endl;
    }

    Byz_invoke(&req, &rep, read_only);

    // Check reply
    PBFT_ASSERT(
      ((option == 2 || option == 0) && rep.size == 8) ||
        (option == 1 && rep.size == Simple_size),
      "Invalid reply");

    // Free reply
    Byz_free_reply(&rep);

    if (i % 10000 == 0)
    {
      LOG_INFO << ms << "ms, " << i << " operations complete\n" << std::endl;
    }

    if (state == MeasureState::measure)
    {
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - now);
      request_latency_histogram[ms / 1000].push_back(duration);
    }
  }
  uint64_t op_count = end_op_id - start_op_id;
  LOG_INFO << "Elapsed time " << t.elapsed() << " for " << op_count
           << "  iterations of operation" << std::endl;
  LOG_INFO << "Throughput " << (double)op_count / (double)t.elapsed()
           << " op/sec" << std::endl;
  LOG_INFO << "Latency " << (double)t.elapsed() * 1000 / (double)op_count
           << " ms/op" << std::endl;

  stats.print_stats();

  LOG_INFO << std::endl << "Latency Request Histogram " << std::endl;
  for (uint64_t i = 0; i < request_latency_histogram.size(); ++i)
  {
    uint64_t sum = 0;
    for (auto duration : request_latency_histogram[i])
    {
      sum += duration.count();
    }
    if (request_latency_histogram[i].size() != 0)
    {
      LOG_INFO << i << "s - " << sum / (request_latency_histogram[i].size())
               << "ms, count:" << request_latency_histogram[i].size()
               << std::endl;
    }
  }
  LOG_INFO << "End Latency Request Histogram" << std::endl;

  Byz_free_request(&req);
}
