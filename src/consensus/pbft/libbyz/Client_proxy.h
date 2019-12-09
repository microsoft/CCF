// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

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

#include "Certificate.h"
#include "ITimer.h"
#include "Message.h"
#include "Node.h"
#include "Reply.h"
#include "Request.h"
#include "ds/logger.h"
#include "libbyz.h"
#include "pbft_assert.h"
#include "receive_message_base.h"
#include "request_id_gen.h"
#include "types.h"

class Reply;
class Request;
class ITimer;

template <class T, class C>
class ClientProxy
{
  // Client proxy used to aggregate requests from clients, submit them to
  // the state machine, collect replies (and receipts), and send them back to
  // the clients. TODO: add support for sending receipts to clients.
public:
  ClientProxy(IMessageReceiveBase& my_replica);
  // Effects: Creates a new ClientProxy object

  using ReplyCallback = std::function<bool(
    C* owner, T caller_rid, int status, uint8_t* reply, size_t len)>;

  bool send_request(
    T caller_rid,
    uint8_t* command,
    size_t len,
    ReplyCallback cb,
    C* owner,
    bool is_read_only = false);
  // Effects: If the number requests outstanding does not exceed the maximum, it
  // sends the request to the service, returns true, and later invokes the
  // callback cb with owner, caller_rid, and the reply to the command.
  // Otherwise, returns false.

  void execute_request(Request* request);

  void recv_reply(Reply* r);
  // Effects: Passes a reply received by the replica to this.

private:
  IMessageReceiveBase& my_replica;
  RequestIdGenerator request_id_generator;

  struct RequestContext
  {
    RequestContext(
      IMessageReceiveBase& replica,
      T caller_rid,
      ReplyCallback cb,
      C* owner,
      std::unique_ptr<Request> req);

    T caller_rid;
    size_t f;
    ReplyCallback cb;
    C* owner;

    Certificate<Reply> t_reps; // Certificate with tentative replies (size 2f+1)
    Certificate<Reply> c_reps; // Certificate with committed replies (size f+1)
    std::unique_ptr<Request> req;

    RequestContext* next;
    RequestContext* prev;
  };
  std::unordered_map<Request_id, std::unique_ptr<RequestContext>> out_reqs;
  static const int Max_outstanding = 1000 * 100;

  // list of outstanding requests used for retransmissions
  // (we only retransmit the request at the head of the queue)
  RequestContext* head;
  RequestContext* tail;

  int n_retrans; // Number of retransmissions of out_req
  int rtimeout; // Timeout period in msecs

  // Maximum retransmission timeout in msecs
  static const int Max_rtimeout = 10000;

  // Minimum retransmission timeout after retransmission
  // in msecs
  static const int Min_rtimeout = 5000;

  // The retransmit timeouts are high due to issues with retransmission
  // https://github.com/microsoft/CCF/issues/617

  void increase_retransmission_timeout();
  void decrease_retransmission_timeout();

  Cycle_counter latency; // Used to measure latency.

  // Multiplier used to obtain retransmission timeout from avg_latency
  static const int Rtimeout_mult = 4;

  static void rtimer_handler(void* owner);
  std::unique_ptr<ITimer> rtimer; // Retransmission timer

  bool primary_only_execution; // true iff f == 0

  void retransmit();
  // Effects: Retransmits any outstanding request at the head of
  // the queue.
};

template <class T, class C>
ClientProxy<T, C>::ClientProxy(IMessageReceiveBase& my_replica) :
  my_replica(my_replica),
  out_reqs(Max_outstanding),
  head(nullptr),
  tail(nullptr),
  n_retrans(0),
  rtimeout(Max_rtimeout),
  rtimer(new ITimer(Max_rtimeout, rtimer_handler, this)),
  primary_only_execution(my_replica.f() == 0)
{}

template <class T, class C>
ClientProxy<T, C>::RequestContext::RequestContext(
  IMessageReceiveBase& replica,
  T caller_rid,
  ReplyCallback cb,
  C* owner,
  std::unique_ptr<Request> req) :
  caller_rid(caller_rid),
  f(replica.f()),
  cb(cb),
  owner(owner),
  t_reps([this]() { return 2 * f + 1; }),
  c_reps([this]() { return f + 1; }),
  req(std::move(req)),
  next(nullptr),
  prev(nullptr)
{}

template <class T, class C>
bool ClientProxy<T, C>::send_request(
  T caller_rid,
  uint8_t* command,
  size_t len,
  ReplyCallback cb,
  C* owner,
  bool is_read_only)
{
  if (out_reqs.size() >= Max_outstanding)
  {
    LOG_FAIL << "Too many outstanding requests, rejecting!" << std::endl;
    return false;
  }

  Request_id rid = request_id_generator.next_rid();
  auto req = std::make_unique<Request>(rid);
  if (req == nullptr)
  {
    return false;
  }

  int max_len;
  char* command_buffer = req->store_command(max_len);
  if (max_len < len)
  {
    return false;
  }

  memcpy(command_buffer, command, len);

  req->authenticate(len, is_read_only);
  req->trim();

  auto req_clone = req->clone();

  auto ctx = std::make_unique<RequestContext>(
    my_replica, caller_rid, cb, owner, std::move(req));

  if (head == nullptr)
  {
    head = tail = ctx.get();
    ctx->prev = ctx->next = nullptr;
    n_retrans = 0;
    rtimer->start();
  }
  else
  {
    tail->next = ctx.get();
    ctx->prev = tail;
    ctx->next = nullptr;
    tail = ctx.get();
  }

  out_reqs.insert({rid, std::move(ctx)});

  execute_request(req_clone);
  return true;
}

template <class T, class C>
void ClientProxy<T, C>::execute_request(Request* request)
{
  if (my_replica.f() == 0)
  {
    if (!my_replica.is_primary())
    {
      my_replica.send(request, my_replica.primary());
      delete request;
      return;
    }
  }
  else
  {
    my_replica.send(request, Node::All_replicas);
  }

  my_replica.handle(request);
}

template <class T, class C>
void ClientProxy<T, C>::recv_reply(Reply* reply)
{
  auto it = out_reqs.find(reply->request_id());
  if (it == out_reqs.end())
  {
    // No request waiting for reply
    delete reply;
    return;
  }

  auto ctx = it->second.get();

  LOG_TRACE << "Received reply msg, request_id:" << reply->request_id()
            << " seqno: " << reply->seqno() << " view " << reply->view()
            << " id: " << reply->id()
            << " tentative: " << (reply->is_tentative() ? "true" : "false")
            << " reps.is_complete: "
            << (ctx->t_reps.is_complete() ? "true" : "false")
            << " reply->full: " << (reply->full() ? "true" : "false")
            << " reps.cvalue: " << (void*)ctx->t_reps.cvalue() << std::endl;

  Certificate<Reply>& reps =
    (reply->is_tentative()) ? ctx->t_reps : ctx->c_reps;

  if (reps.is_complete())
  {
    // We have a complete certificate without a full reply.
    if (!reply->full() || !reply->match(reps.cvalue()))
    {
      delete reply;
      return;
    }
  }
  else
  {
    if (reply->id() != my_replica.my_id())
    {
      reps.add(reply);
    }
    else
    {
      reps.add_mine(reply);
    }

    reply = (reps.is_complete() && reps.cvalue()->full()) ?
      reps.cvalue_clear() :
      nullptr;
  }

  if (reply == nullptr)
  {
    return;
  }

  rtimer->stop();

  int reply_len;
  char* reply_buffer = reply->reply(reply_len);

  LOG_DEBUG << "Received complete reply request_id:" << reply->request_id()
            << " client id: " << reply->id() << " seqno: " << reply->seqno()
            << " view " << reply->view() << std::endl;

  // TODO: Should the return value of this function be checked here?
  ctx->cb(ctx->owner, ctx->caller_rid, 0, (uint8_t*)reply_buffer, reply_len);

  if (ctx->prev == nullptr)
  {
    PBFT_ASSERT(head == ctx, "Invalid state");
    head = ctx->next;
  }
  else
  {
    ctx->prev->next = ctx->next;
  }

  if (ctx->next == nullptr)
  {
    PBFT_ASSERT(tail == ctx, "Invalid state");
    tail = ctx->prev;
  }
  else
  {
    ctx->next->prev = ctx->prev;
  }

  out_reqs.erase(it);
  delete reply;
  decrease_retransmission_timeout();

  n_retrans = 0;

  if (head != nullptr)
  {
    rtimer->start();
  }
}

template <class T, class C>
void ClientProxy<T, C>::rtimer_handler(void* owner)
{
  ((ClientProxy*)owner)->retransmit();
}

template <class T, class C>
void ClientProxy<T, C>::increase_retransmission_timeout()
{
  rtimeout = rtimeout * 2;
  if (rtimeout > Max_rtimeout)
  {
    rtimeout = Max_rtimeout;
  }
  rtimer->adjust(rtimeout);
}

template <class T, class C>
void ClientProxy<T, C>::decrease_retransmission_timeout()
{
  rtimeout = rtimeout - 100;
  if (rtimeout < Min_rtimeout)
  {
    rtimeout = Min_rtimeout;
  }
  rtimer->adjust(rtimeout);
}

template <class T, class C>
void ClientProxy<T, C>::retransmit()
{
  // Retransmit any outstanding request.
  static const int thresh = 1;

  if (head != nullptr)
  {
    RequestContext* ctx = head;
    Request* out_req = ctx->req.get();

    LOG_DEBUG << "Retransmitting req id: " << out_req->request_id()
              << std::endl;
    INCR_OP(req_retrans);

#ifndef ENFORCE_EXACTLY_ONCE
    ctx->t_reps.clear();
    ctx->c_reps.clear();
#endif

    n_retrans++;
    bool ro = out_req->is_read_only();
    bool change = (ro || out_req->replier() >= 0) && n_retrans > thresh;

    if (change)
    {
      // Compute new authenticator for request
      out_req->re_authenticate(change);
      if (ro && change)
      {
        ctx->t_reps.clear();
      }
    }

    LOG_DEBUG << "Client_proxy retransmitting request, rid:"
              << out_req->request_id() << std::endl;

    if (
      out_req->is_read_only() || n_retrans > thresh ||
      out_req->size() > Request::big_req_thresh)
    {
      // read-only requests, requests retransmitted more than
      // thresh times, and big requests are multicast to all
      // replicas.
      auto req_clone = out_req->clone();
      execute_request(req_clone);
    }
    else
    {
      // read-write requests are sent to the primary only.
      my_replica.send(out_req, my_replica.primary());
    }
  }

  if (n_retrans > thresh)
  {
    increase_retransmission_timeout();
  }

  rtimer->restart();
}
