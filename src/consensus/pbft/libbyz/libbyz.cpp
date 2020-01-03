// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "libbyz.h"

#include "Client.h"
#include "Replica.h"
#include "Reply.h"
#include "Request.h"
#include "Statistics.h"
#include "globalstate.h"
#include "receive_message_base.h"

#include <random>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

int Byz_init_client(const NodeInfo& node_info, INetwork* network)
{
  client = std::make_unique<Client>(node_info, network);
  set_node((Node*)client.get());
  return 0;
}

void Byz_reset_client()
{
  ((Client*)get_node())->reset();
}

int Byz_alloc_request(Byz_req* req, int size)
{
  Request* request = new Request((Request_id)0);
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

int Byz_send_request(Byz_req* req, bool ro)
{
  Request* request = (Request*)req->opaque;
  request->request_id() = ((Client*)get_node())->get_rid();
  request->authenticate(req->size, ro);

  bool retval = ((Client*)get_node())->send_request(request);
  return (retval) ? 0 : -1;
}

int Byz_recv_reply(Byz_rep* rep)
{
  Reply* reply = ((Client*)get_node())->recv_reply();
  if (reply == NULL)
  {
    return -1;
  }
  rep->contents = reply->reply(rep->size);
  rep->opaque = reply;
  return 0;
}

int Byz_invoke(Byz_req* req, Byz_rep* rep, bool ro)
{
  if (Byz_send_request(req, ro) == -1)
  {
    return -1;
  }
  return Byz_recv_reply(rep);
}

void Byz_free_request(Byz_req* req)
{
  Request* request = (Request*)req->opaque;
  delete request;
}

void Byz_free_reply(Byz_rep* rep)
{
  Reply* reply = (Reply*)rep->opaque;
  delete reply;
}

void Byz_configure_principals()
{
  get_node()->configure_principals();
}

void Byz_add_principal(const PrincipalInfo& principal_info)
{
  get_node()->add_principal(principal_info);
}

void Byz_start_replica()
{
  get_replica()->recv_start();
  stats.zero_stats();
}

int Byz_init_replica(
  const NodeInfo& node_info,
  char* mem,
  unsigned int size,
  ExecCommand exec,
  void (*comp_ndet)(Seqno, Byz_buffer*),
  int ndet_max_len,
  INetwork* network,
  std::unique_ptr<consensus::LedgerEnclave> ledger,
  IMessageReceiveBase** message_receiver)
{
  // Initialize random number generator
  replica =
    std::make_unique<Replica>(node_info, mem, size, network, std::move(ledger));
  set_node((Node*)replica.get());

  if (message_receiver != nullptr)
  {
    *message_receiver = replica.get();
  }

  // Register service-specific functions.
  get_replica()->register_exec(exec);
  get_replica()->register_nondet_choices(comp_ndet, ndet_max_len);

  auto used_bytes = get_replica()->used_state_bytes();
  stats.zero_stats();
  return used_bytes;
}

void Byz_modify(void* mem, int size)
{
  get_replica()->modify(mem, size);
}

void Byz_replica_run()
{
  get_replica()->recv();
}

void Byz_reset_stats()
{
  stats.zero_stats();
}

void Byz_print_stats()
{
  stats.print_stats();
}
