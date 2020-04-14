// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "libbyz.h"

#include "global_state.h"
#include "receive_message_base.h"
#include "replica.h"
#include "reply.h"
#include "request.h"
#include "statistics.h"

#include <random>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

int Byz_alloc_request(Byz_req* req, int size)
{
  Request* request = new Request((Request_id)0, -1, size);
  if (request == 0)
  {
    return -1;
  }

  int len;
  req->contents = request->store_command(len);
  req->size = len;
  req->opaque = (void*)request;
  return 0;
}

void Byz_configure_principals()
{
  pbft::GlobalState::get_node().configure_principals();
}

void Byz_add_principal(const PrincipalInfo& principal_info)
{
  pbft::GlobalState::get_node().add_principal(principal_info);
}

void Byz_start_replica()
{
  pbft::GlobalState::get_replica().recv_start();
  stats.zero_stats();
}

int Byz_init_replica(
  const NodeInfo& node_info,
  char* mem,
  unsigned int size,
  ExecCommand exec,
  INetwork* network,
  pbft::RequestsMap& pbft_requests_map,
  pbft::PrePreparesMap& pbft_pre_prepares_map,
  ccf::Signatures& signatures,
  pbft::PbftStore& store,
  IMessageReceiveBase** message_receiver)
{
  // Initialize random number generator
  pbft::GlobalState::set_replica(std::make_unique<Replica>(
    node_info,
    mem,
    size,
    network,
    pbft_requests_map,
    pbft_pre_prepares_map,
    signatures,
    store));

  if (message_receiver != nullptr)
  {
    *message_receiver = &pbft::GlobalState::get_replica();
  }

  // Register service-specific functions.
  pbft::GlobalState::get_replica().register_exec(exec);
  pbft::GlobalState::get_replica().set_next_expected_sig_offset();

  auto used_bytes = pbft::GlobalState::get_replica().used_state_bytes();
  stats.zero_stats();
  return used_bytes;
}

void Byz_modify(void* mem, int size)
{
  pbft::GlobalState::get_replica().modify(mem, size);
}

void Byz_reset_stats()
{
  stats.zero_stats();
}

void Byz_print_stats()
{
  stats.print_stats();
}

bool Byz_execution_pending()
{
  return pbft::GlobalState::get_replica().IsExecutionPending();
}