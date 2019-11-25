// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#ifndef INSIDE_ENCLAVE
#  include <stdio.h>
#  include <stdlib.h>
#  include <string.h>
#endif

#ifndef INSIDE_ENCLAVE
#  include <sys/time.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#include "Client.h"
#include "ITimer.h"
#include "Message.h"
#include "Reply.h"
#include "Request.h"
#include "ds/logger.h"
#include "network.h"
#include "pbft_assert.h"

Client::Client(const NodeInfo& node_info, INetwork* network) :
  Node(node_info),
  t_reps([this]() { return 2 * f() + 1; }),
  c_reps([this]() { return f() + 1; })
{
  // Fail if node is a replica.
  LOG_INFO << "my id " << id() << std::endl;
  if (is_replica(id()))
  {
    PBFT_FAIL("Node is a replica");
  }

  rtimeout = 150; // Initial timeout value
  rtimer = new ITimer(rtimeout, rtimer_handler, this);

  out_rid = new_rid();
  out_req = 0;

  init_network(std::unique_ptr<INetwork>(network));
}

Client::~Client()
{
  delete rtimer;
}

void Client::reset()
{
  rtimeout = 150;
}

bool Client::send_request(Request* req)
{
  LOG_DEBUG << "Send msg" << std::endl;
  bool ro = req->is_read_only();
  if (out_req == 0)
  {
    // Send request to service
    if (ro || req->size() > Request::big_req_thresh)
    {
      // read-only requests and big requests are multicast to all replicas.
      send(req, All_replicas);
    }
    else
    {
      // read-write requests are sent to the primary only.
      send(req, primary());
    }
    out_req = req;
    need_auth = false;
    n_retrans = 0;

    rtimer->start();
    return true;
  }
  else
  {
    // Another request is being processed.
    return false;
  }
}

Reply* Client::recv_reply()
{
  if (out_req == 0)
  {
    // Nothing to wait for.
    return 0;
  }

  //
  // Wait for reply
  //
  while (1)
  {
    Message* m = recv();

    Reply* rep;
    if (
      !Reply::convert(m, rep) || rep->request_id() != out_rid ||
      !rep->pre_verify())
    {
      delete m;
      continue;
    }

    LOG_DEBUG << "Received reply msg, request_id:" << rep->request_id()
              << " seqno: " << rep->seqno() << " view " << rep->view()
              << " tentative: " << rep->is_tentative()
              << " reps.is_complete: " << t_reps.is_complete()
              << " reps.cvalue: " << (void*)t_reps.cvalue() << std::endl;

    Certificate<Reply>& reps = (rep->is_tentative()) ? t_reps : c_reps;
    if (reps.is_complete())
    {
      // We have a complete certificate without a full reply.
      if (!rep->full() || !rep->match(reps.cvalue()))
      {
        delete rep;
        continue;
      }
    }
    else
    {
      reps.add(rep);
      rep =
        (reps.is_complete() && reps.cvalue()->full()) ? reps.cvalue_clear() : 0;
    }

    if (rep)
    {
      LOG_DEBUG << "request " << rep->request_id() << " has committed"
                << std::endl;

      out_rid = new_rid();
      rtimer->stop();
      out_req = 0;
      t_reps.clear();
      c_reps.clear();

      // Choose view in returned rep. TODO: could make performance
      // more robust to attacks by picking the median view in the
      // certificate.
      v = rep->view();
      cur_primary = v % num_replicas;

      decrease_retransmission_timeout();

      return rep;
    }
  }
}

void Client::rtimer_handler(void* owner)
{
  ((Client*)owner)->retransmit();
}

void Client::increase_retransmission_timeout()
{
  rtimeout = rtimeout * 2;
  if (rtimeout > Max_rtimeout)
  {
    rtimeout = Max_rtimeout;
  }
  rtimer->adjust(rtimeout);
}

void Client::decrease_retransmission_timeout()
{
  rtimeout = rtimeout - 100;
  if (rtimeout < Min_rtimeout)
  {
    rtimeout = Min_rtimeout;
  }
  rtimer->adjust(rtimeout);
}

void Client::retransmit()
{
  // Retransmit any outstanding request.
  static const int thresh = 1;
  static const int nk_thresh = 4;
  static const int nk_thresh_1 = 100;

  if (out_req != 0)
  {
    LOG_DEBUG << "Retransmitting req id: " << out_req->request_id()
              << std::endl;
    INCR_OP(req_retrans);

#ifndef ENFORCE_EXACTLY_ONCE
    t_reps.clear();
#endif

    n_retrans++;

    bool ro = out_req->is_read_only();
    bool change = (ro || out_req->replier() >= 0) && n_retrans > thresh;

    if (need_auth || change)
    {
      // Compute new authenticator for request
      out_req->re_authenticate(change);
      need_auth = false;
      if (ro && change)
      {
        t_reps.clear();
      }
    }

    if (
      out_req->is_read_only() || n_retrans > thresh ||
      out_req->size() > Request::big_req_thresh)
    {
      // read-only requests, requests retransmitted more than
      // mcast_threshold times, and big requests are multicast to all
      // replicas.
      send(out_req, All_replicas);
    }
    else
    {
      // read-write requests are sent to the primary only.
      send(out_req, primary());
    }
  }

  if (n_retrans > thresh)
  {
    increase_retransmission_timeout();
  }

  rtimer->restart();
}