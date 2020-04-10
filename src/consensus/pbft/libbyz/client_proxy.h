// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "certificate.h"
#include "ds/logger.h"
#include "ds/spin_lock.h"
#include "ds/thread_messaging.h"
#include "itimer.h"
#include "libbyz.h"
#include "message.h"
#include "node.h"
#include "pbft_assert.h"
#include "receive_message_base.h"
#include "reply.h"
#include "request.h"
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
  // the clients.
public:
  ClientProxy(
    IMessageReceiveBase& my_replica,
    int min_rtimeout = 2000,
    int max_rtimeout = 3000);
  // Effects: Creates a new ClientProxy object

  using ReplyCallback = std::function<bool(
    C* owner, T caller_rid, int status, std::vector<uint8_t>& data)>;

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

  void periodic(std::chrono::milliseconds elapsed);
  kv::Consensus::Statistics get_statistics();
  void reset_statistics();

  struct ExecuteRequestMsg
  {
    std::unique_ptr<Request> request;
    ClientProxy<T, C>* self;
  };
  static void execute_request_cb(
    std::unique_ptr<enclave::Tmsg<ExecuteRequestMsg>> msg);
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
      uint16_t reply_thread,
      uint64_t start_time,
      std::unique_ptr<Request> req);

    T caller_rid;
    size_t f;
    ReplyCallback cb;
    C* owner;
    uint16_t reply_thread;

    Certificate<Reply> t_reps; // Certificate with tentative replies (size 2f+1)
    Certificate<Reply> c_reps; // Certificate with committed replies (size f+1)
    std::unique_ptr<Request> req;
    uint64_t start_time;

    RequestContext* next;
    RequestContext* prev;
  };
  std::unordered_map<Request_id, std::unique_ptr<RequestContext>> out_reqs;
  std::atomic<uint64_t> current_outstanding = 0;
  std::atomic<uint64_t> milliseconds_since_start = 0;
  struct Statistics
  {
    std::atomic<uint32_t> time_spent = 0;
    std::atomic<uint32_t> count_num_samples = 0;
  };

  Statistics current_statistics;
  Statistics previous_statistics;
  bool should_reset_statistics = true;

  static const int Max_outstanding = 10'000;
  SpinLock lock;

  struct ReplyCbMsg
  {
    C* owner;
    T caller_rid;
    std::vector<uint8_t> data;
    ReplyCallback cb;
  };
  static void send_reply(std::unique_ptr<enclave::Tmsg<ReplyCbMsg>> msg);

  // list of outstanding requests used for retransmissions
  // (we only retransmit the request at the head of the queue)
  RequestContext* head;
  RequestContext* tail;

  int n_retrans; // Number of retransmissions of out_req
  int rtimeout; // Timeout period in msecs

  // Maximum retransmission timeout in msecs
  int max_rtimeout;

  // Minimum retransmission timeout after retransmission
  // in msecs
  int min_rtimeout;

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
ClientProxy<T, C>::ClientProxy(
  IMessageReceiveBase& my_replica, int min_rtimeout_, int max_rtimeout_) :
  min_rtimeout(min_rtimeout_),
  max_rtimeout(max_rtimeout_),
  my_replica(my_replica),
  out_reqs(Max_outstanding),
  head(nullptr),
  tail(nullptr),
  n_retrans(0),
  rtimeout(max_rtimeout_),
  rtimer(new ITimer(max_rtimeout, rtimer_handler, this)),
  primary_only_execution(my_replica.f() == 0)
{}

template <class T, class C>
ClientProxy<T, C>::RequestContext::RequestContext(
  IMessageReceiveBase& replica,
  T caller_rid,
  ReplyCallback cb,
  C* owner,
  uint16_t reply_thread,
  uint64_t start_time,
  std::unique_ptr<Request> req) :
  caller_rid(caller_rid),
  f(replica.f()),
  reply_thread(reply_thread),
  start_time(start_time),
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
  if (current_outstanding.fetch_add(1) >= Max_outstanding)
  {
    current_outstanding.fetch_sub(1);
    LOG_FAIL << "Too many outstanding requests, rejecting!" << std::endl;
    return false;
  }

  Request_id rid = request_id_generator.next_rid();
  auto req = std::make_unique<Request>(rid, -1, len);
  if (req == nullptr)
  {
    current_outstanding.fetch_sub(1);
    return false;
  }

  int max_len;
  char* command_buffer = req->store_command(max_len);
  if (max_len < len)
  {
    current_outstanding.fetch_sub(1);
    return false;
  }

  memcpy(command_buffer, command, len);

  req->authenticate(len, is_read_only);

  auto req_clone = req->clone();

  auto ctx = std::make_unique<RequestContext>(
    my_replica,
    caller_rid,
    cb,
    owner,
    thread_ids[std::this_thread::get_id()],
    milliseconds_since_start,
    std::move(req));

  {
    std::lock_guard<SpinLock> mguard(lock);
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
  }

  auto msg =
    std::make_unique<enclave::Tmsg<ExecuteRequestMsg>>(execute_request_cb);
  msg->data.self = this;
  msg->data.request.reset(std::move(req_clone));

  if (enclave::ThreadMessaging::thread_count > 1)
  {
    enclave::ThreadMessaging::thread_messaging.add_task<ExecuteRequestMsg>(
      enclave::ThreadMessaging::main_thread, std::move(msg));
  }
  else
  {
    execute_request_cb(std::move(msg));
  }

  return true;
}

template <class T, class C>
void ClientProxy<T, C>::execute_request_cb(
  std::unique_ptr<enclave::Tmsg<ExecuteRequestMsg>> msg)
{
  auto self = msg->data.self;
  self->execute_request(msg->data.request.release());
}

template <class T, class C>
void ClientProxy<T, C>::execute_request(Request* request)
{
  if (
    thread_ids[std::this_thread::get_id()] !=
    enclave::ThreadMessaging::main_thread)
  {
    throw std::logic_error("Execution on incorrect thread");
  }
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

  my_replica.process_message(request);
}

template <class T, class C>
void ClientProxy<T, C>::send_reply(
  std::unique_ptr<enclave::Tmsg<ReplyCbMsg>> msg)
{
  msg->data.cb(msg->data.owner, msg->data.caller_rid, 0, msg->data.data);
}

template <class T, class C>
void ClientProxy<T, C>::recv_reply(Reply* reply)
{
  RequestContext* ctx;
  {
    std::lock_guard<SpinLock> mguard(lock);
    auto it = out_reqs.find(reply->request_id());
    if (it == out_reqs.end())
    {
      // No request waiting for reply
      delete reply;
      return;
    }

    ctx = it->second.get();
    current_statistics.time_spent.fetch_add(
      milliseconds_since_start - ctx->start_time);
    current_statistics.count_num_samples++;
  }

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
  uint8_t* reply_buffer = (uint8_t*)reply->reply(reply_len);

  LOG_DEBUG << "Received complete reply request_id:" << reply->request_id()
            << " client id: " << reply->id() << " seqno: " << reply->seqno()
            << " view " << reply->view() << std::endl;

  auto msg = std::make_unique<enclave::Tmsg<ReplyCbMsg>>(&send_reply);
  msg->data.owner = ctx->owner;
  msg->data.caller_rid = ctx->caller_rid;
  msg->data.cb = ctx->cb;
  msg->data.data.assign(reply_buffer, reply_buffer + reply_len);

  if (enclave::ThreadMessaging::thread_count > 1)
  {
    enclave::ThreadMessaging::thread_messaging.add_task<ReplyCbMsg>(
      ctx->reply_thread, std::move(msg));
  }
  else
  {
    send_reply(std::move(msg));
  }

  {
    std::lock_guard<SpinLock> mguard(lock);
    auto it = out_reqs.find(reply->request_id());

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
    current_outstanding.fetch_sub(1);
    delete reply;
    decrease_retransmission_timeout();

    n_retrans = 0;

    if (head != nullptr)
    {
      rtimer->start();
    }
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
  if (rtimeout > max_rtimeout)
  {
    rtimeout = max_rtimeout;
  }
  rtimer->adjust(rtimeout);
}

template <class T, class C>
void ClientProxy<T, C>::decrease_retransmission_timeout()
{
  rtimeout = rtimeout - 100;
  if (rtimeout < min_rtimeout)
  {
    rtimeout = min_rtimeout;
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

    LOG_INFO_FMT("Retransmitting req id: {}", out_req->request_id());
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

template <class T, class C>
void ClientProxy<T, C>::periodic(std::chrono::milliseconds elapsed)
{
  milliseconds_since_start.fetch_add(elapsed.count());
}

template <class T, class C>
void ClientProxy<T, C>::reset_statistics()
{
  should_reset_statistics = true;
}

template <class T, class C>
kv::Consensus::Statistics ClientProxy<T, C>::get_statistics()
{
  if (should_reset_statistics)
  {
    previous_statistics.time_spent = current_statistics.time_spent.exchange(0);
    previous_statistics.count_num_samples =
      current_statistics.count_num_samples.exchange(0);
    should_reset_statistics = false;
  }

  return {
    previous_statistics.time_spent, previous_statistics.count_num_samples, 0};
}