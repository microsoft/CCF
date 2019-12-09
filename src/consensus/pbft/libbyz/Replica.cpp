// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#ifndef INSIDE_ENCLAVE
#  include <stdio.h>
#  include <string.h>
#endif

#include <limits.h>

#ifndef INSIDE_ENCLAVE
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <stdlib.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#include "Checkpoint.h"
#include "Commit.h"
#include "Data.h"
#include "Fetch.h"
#include "ITimer.h"
#include "K_max.h"
#include "Message_tags.h"
#include "Meta_data.h"
#include "Meta_data_d.h"
#include "New_view.h"
#include "Pre_prepare.h"
#include "Prepare.h"
#include "Prepared_cert.h"
#include "Principal.h"
#include "Query_stable.h"
#include "Replica.h"
#include "Reply.h"
#include "Reply_stable.h"
#include "Request.h"
#include "Statistics.h"
#include "Status.h"
#include "View_change.h"
#include "View_change_ack.h"
#include "ds/logger.h"
#include "ds/serialized.h"
#include "ledger.h"
#include "network.h"
#include "pbft_assert.h"

// Global replica object.
Replica* replica;

template <class T>
void Replica::retransmit(T* m, Time cur, Time tsent, Principal* p)
{
  // do not retransmit messages that we just sent for the
  // first time
  if (diff_time(cur, tsent) > 10000)
  {
    // Retransmit message
    INCR_OP(message_counts_retransmitted[m->tag()]);
    send(m, p->pid());
  }
}

Replica::Replica(
  const NodeInfo& node_info,
  char* mem,
  size_t nbytes,
  INetwork* network,
  std::unique_ptr<consensus::LedgerEnclave> ledger) :
  Node(node_info),
  rqueue(),
  ro_rqueue(),
  plog(max_out),
  clog(max_out),
  elog(max_out * 2, 0),
  stable_checkpoints(num_of_replicas()),
#ifdef ENFORCE_EXACTLY_ONCE
  replies(mem, nbytes, num_principals),
#else
  replies(mem, nbytes),
#endif
  rep_cb(nullptr),
  global_commit_cb(nullptr),
  state(this, mem, nbytes),
  vi(
    node_id,
    0,
    64) // make this dynamic - https://github.com/microsoft/CCF/issues/385
{
  // Fail if node is not a replica.
  if (!is_replica(id()))
  {
    LOG_FATAL << "Node is not a replica " << id() << std::endl;
  }

  // Fail if the state Merkle tree cannot support the requested number of bytes
  size_t max_mem_bytes = PLevelSize[PLevels - 1] * Block_size;
  if (nbytes > max_mem_bytes)
  {
    LOG_FATAL << "Unable to support requested memory size " << nbytes << " > "
              << max_mem_bytes << std::endl;
  }

  init_network(std::unique_ptr<INetwork>(network));

  next_pp_seqno = 0;
  last_stable = 0;
  low_bound = 0;

  last_prepared = 0;
  last_executed = 0;
  last_tentative_execute = 0;

  last_status = 0;

  limbo = false;
  has_nv_state = true;

  nbreqs = 0;
  nbrounds = 0;

  // Read view change, status, and recovery timeouts from node_info
  long vt, st, rt = 0;
  vt = node_info.general_info.view_timeout;
  st = node_info.general_info.status_timeout;
  rt = node_info.general_info.recovery_timeout;

  // Create timers and randomize times to avoid collisions.

  vtimer = new ITimer(vt + (uint64_t)id() % 100, vtimer_handler, this);
  stimer = new ITimer(st + (uint64_t)id() % 100, stimer_handler, this);
  btimer =
    new ITimer(max_pre_prepare_request_batch_wait_ms, btimer_handler, this);

  cid_vtimer = 0;
  rid_vtimer = 0;

#ifdef DEBUG_SLOW
  debug_slow_timer = new ITimer(10 * 60 * 1000, debug_slow_timer_handler, this);
  debug_slow_timer->start();
#endif

#ifdef PROACTIVE_RECOVERY
  // Skew recoveries. It is important for nodes to recover in the reverse order
  // of their node ids to avoid a view-change every recovery which would degrade
  // performance.
  rtimer = new ITimer(rt, rec_timer_handler, this);
  rec_ready = false;
  rtimer->start();
#endif

  ntimer = new ITimer(30000 / max_out, ntimer_handler, this);

  recovering = false;
  qs = 0;
  rr = 0;
  recovery_point = Seqno_max;
  max_rec_n = 0;

  exec_command = nullptr;
  non_det_choices = 0;

  if (ledger)
  {
    ledger_replay = std::make_unique<LedgerReplay>();
    ledger_writer = std::make_unique<LedgerWriter>(std::move(ledger));
  }
}

void Replica::register_exec(ExecCommand e)
{
  exec_command = e;
}

void Replica::register_nondet_choices(
  void (*n)(Seqno, Byz_buffer*), int max_len)
{
  non_det_choices = n;
  max_nondet_choice_len = max_len;
}

void Replica::compute_non_det(Seqno s, char* b, int* b_len)
{
  if (non_det_choices == 0)
  {
    *b_len = 0;
    return;
  }
  Byz_buffer buf;
  buf.contents = b;
  buf.size = *b_len;
  non_det_choices(s, &buf);
  *b_len = buf.size;
}

Replica::~Replica()
{
  delete vtimer;
#ifdef PROACTIVE_RECOVERY
  delete rtimer;
#endif
  delete stimer;
  delete btimer;
#ifdef DEBUG_SLOW
  delete debug_slow_timer;
#endif
}

void Replica::receive_message(const uint8_t* data, uint32_t size)
{
  if (size > Max_message_size)
  {
    LOG_FAIL << "Received message size exceeds message: " << size << std::endl;
  }
  uint64_t alloc_size = std::max(size, (uint32_t)Max_message_size);
  Message* m = new Message(alloc_size);
  // TODO: remove this memcpy
  memcpy(m->contents(), data, size);
  if (pre_verify(m))
  {
    recv_process_one_msg(m);
  }
  else
  {
    delete m;
  }
}

bool Replica::compare_execution_results(
  const ByzInfo& info, Pre_prepare* pre_prepare)
{
  auto& pp_root = pre_prepare->get_full_state_merkle_root();
  auto& r_pp_root = pre_prepare->get_replicated_state_merkle_root();
  if (!std::equal(
        std::begin(pp_root),
        std::end(pp_root),
        std::begin(info.full_state_merkle_root)))
  {
    LOG_FAIL << "Full state merkle root between execution and the pre_prepare "
                "message does not match, seqno:"
             << pre_prepare->seqno() << std::endl;
    return false;
  }

  if (!std::equal(
        std::begin(r_pp_root),
        std::end(r_pp_root),
        std::begin(info.replicated_state_merkle_root)))
  {
    LOG_FAIL << "Replicated state merkle root between execution and the "
                "pre_prepare message does not match, seqno:"
             << pre_prepare->seqno() << std::endl;
    return false;
  }

  auto tx_ctx = pre_prepare->get_ctx();
  if (tx_ctx != info.ctx && info.ctx != std::numeric_limits<int64_t>::min())
  {
    LOG_FAIL << "User ctx between execution and the pre_prepare message "
                "does not match, seqno:"
             << pre_prepare->seqno() << ", tx_ctx:" << tx_ctx
             << ", info.ctx:" << info.ctx << std::endl;
    return false;
  }
  return true;
}

bool Replica::apply_ledger_data(const std::vector<uint8_t>& data)
{
  PBFT_ASSERT(ledger_replay, "ledger_replay should be initialized");

  if (data.empty())
  {
    LOG_FAIL << "Received empty entries" << std::endl;
    return false;
  }

  auto executable_pps = ledger_replay->process_data(
    data, rqueue, brt, *ledger_writer.get(), last_executed);

  for (auto& executable_pp : executable_pps)
  {
    auto seqno = executable_pp->seqno();

    ByzInfo info;
    if (execute_tentative(executable_pp.get(), info))
    {
      auto batch_info = compare_execution_results(info, executable_pp.get());
      if (!batch_info)
      {
        return false;
      }

      next_pp_seqno = seqno;

      if (seqno > last_prepared)
      {
        last_prepared = seqno;
      }

      if (global_commit_cb != nullptr)
      {
        global_commit_cb(
          executable_pp->get_ctx(), executable_pp->view(), global_commit_ctx);
      }

      last_executed++;

      if (last_executed % checkpoint_interval == 0)
      {
        mark_stable(last_executed, true);
      }
    }
    else
    {
      LOG_DEBUG << "Received entries could not be processed. Received seqno: "
                << seqno
                << ". Truncating ledger to last executed: " << last_executed
                << std::endl;
      ledger_replay->clear_requests(rqueue, brt);
      ledger_writer->truncate(last_executed);
      return false;
    }
  }
  return true;
}

void Replica::init_state()
{
  // Compute digest of initial state and first checkpoint.
  state.compute_full_digest();
}

void Replica::recv_start()
{
  init_state();

  // Start status and authentication freshness timers
  stimer->start();
  if (id() == primary())
  {
    ntimer->start();
  }

  // Allow recoveries
  rec_ready = true;

  LOG_INFO << "Replica ready" << std::endl;
// TODO(#pbft): stub out, INSIDE_ENCLAVE
#ifndef INSIDE_ENCLAVE
  std::cout << "Replica ready" << std::endl;
#endif

  if (state.in_check_state())
  {
    state.check_state();
  }
}

void Replica::recv_process_one_msg(Message* m)
{
  PBFT_ASSERT(m->tag() != New_key_tag, "Tag no longer supported");

  switch (m->tag())
  {
    case Request_tag:
      gen_handle<Request>(m);
      break;

    case Reply_tag:
      gen_handle<Reply>(m);
      break;

    case Pre_prepare_tag:
      gen_handle<Pre_prepare>(m);
      break;

    case Prepare_tag:
      gen_handle<Prepare>(m);
      break;

    case Commit_tag:
      gen_handle<Commit>(m);
      break;

    case Checkpoint_tag:
      gen_handle<Checkpoint>(m);
      break;

#ifndef USE_PKEY_VIEW_CHANGES
    case View_change_ack_tag:
      gen_handle<View_change_ack>(m);
      break;
#endif

    case Status_tag:
      gen_handle<Status>(m);
      break;

    case Fetch_tag:
      gen_handle<Fetch>(m);
      break;

    case Query_stable_tag:
      gen_handle<Query_stable>(m);
      break;

    case Reply_stable_tag:
      gen_handle<Reply_stable>(m);
      break;

    case Meta_data_tag:
      gen_handle<Meta_data>(m);
      break;

    case Meta_data_d_tag:
      gen_handle<Meta_data_d>(m);
      break;

    case Data_tag:
      gen_handle<Data>(m);
      break;

    case View_change_tag:
      gen_handle<View_change>(m);
      break;

    case New_view_tag:
      gen_handle<New_view>(m);
      break;

    case New_principal_tag:
      gen_handle<New_principal>(m);
      break;

    case Network_open_tag:
      gen_handle<Network_open>(m);
      break;

    default:
      // Unknown message type.
      delete m;
  }

  if (state.in_check_state())
  {
    state.check_state();
  }
}

template <class T>
bool Replica::gen_pre_verify(Message* m)
{
  T* n;
  if (T::convert(m, n))
  {
    return n->pre_verify();
  }

  return false;
}

bool Replica::pre_verify(Message* m)
{
  switch (m->tag())
  {
    case Request_tag:
      return gen_pre_verify<Request>(m);

    case Reply_tag:
      return gen_pre_verify<Reply>(m);

    case Pre_prepare_tag:
      return gen_pre_verify<Pre_prepare>(m);

    case Prepare_tag:
      return gen_pre_verify<Prepare>(m);

    case Commit_tag:
      return gen_pre_verify<Commit>(m);

    case Checkpoint_tag:
      return gen_pre_verify<Checkpoint>(m);

    case Status_tag:
      return gen_pre_verify<Status>(m);

    case Fetch_tag:
      return gen_pre_verify<Fetch>(m);

    case View_change_tag:
      return gen_pre_verify<View_change>(m);

    case New_view_tag:
      return gen_pre_verify<New_view>(m);

#ifndef USE_PKEY_VIEW_CHANGES
    case View_change_ack_tag:
#endif

    case Query_stable_tag:
    case Reply_stable_tag:
    case Meta_data_tag:
    case Meta_data_d_tag:
    case Data_tag:
    case New_principal_tag:
    case Network_open_tag:
      return true;

    default:
      // Unknown message type.
      return false;
  }
}

void Replica::recv()
{
  while (1)
  {
    Message* m = Node::recv();
    recv_process_one_msg(m);
  }
}

void Replica::handle(Request* m)
{
  bool ro = m->is_read_only();

  Digest rd = m->digest();
  LOG_TRACE << "Received request with rid: " << m->request_id()
            << " id:" << id() << " primary:" << primary()
            << " with cid: " << m->client_id()
            << " current seqno: " << next_pp_seqno
            << " last executed: " << last_executed << " digest: " << rd.hash()
            << std::endl;

  if (has_complete_new_view())
  {
    LOG_TRACE << "Received request with rid: " << m->request_id()
              << " with cid: " << m->client_id() << std::endl;
#if 0
    // TODO: Fix execution of read-only requests
    if (ro)
    {
      // Read-only requests.
      if (execute_read_only(m) || !ro_rqueue.append(m))
        delete m;

      return;
    }
#endif

#ifdef ENFORCE_EXACTLY_ONCE
    int client_id = m->client_id();
    Request_id rid = m->request_id();
    Request_id last_rid = replies.req_id(client_id);
    if (last_rid < rid)
#endif
    {
      if (id() == primary())
      {
        if (rqueue.append(m))
        {
          if (!wait_for_network_to_open)
          {
            send_pre_prepare();
          }
          return;
        }
      }
      else
      {
        if (m->size() > Request::big_req_thresh && brt.add_request(m))
        {
          return;
        }

        if (rqueue.append(m))
        {
          if (!limbo && f() > 0)
          {
            send(m, primary());
            start_vtimer_if_request_waiting();
          }
          return;
        }
      }
    }
#ifdef ENFORCE_EXACTLY_ONCE
    else if (last_rid == rid)
    {
      // Retransmit reply.
      if (replies.is_committed(client_id))
      {
        LOG_DEBUG << "Retransmit reply for client id: " << client_id
                  << " in view: " << view() << " with rid: " << rid
                  << std::endl;
        INCR_OP(message_counts_retransmitted[Reply_tag]);
        replies.send_reply(client_id, view(), id(), false);
      }
      else if (id() != primary() && rqueue.append(m))
      {
        start_vtimer_if_request_waiting();
        return;
      }
    }
#endif
  }
  else
  {
    if (m->size() > Request::big_req_thresh && !ro && brt.add_request(m))
    {
      return;
    }
  }

  delete m;
}

void Replica::send_pre_prepare(bool do_not_wait_for_batch_size)
{
  PBFT_ASSERT(primary() == node_id, "Non-primary called send_pre_prepare");

  // If rqueue is empty there are no requests for which to send
  // pre_prepare and a pre-prepare cannot be sent if the seqno exceeds
  // the maximum window or the replica does not have the new view.
  if (
    (rqueue.size() >= min_pre_prepare_batch_size ||
     (do_not_wait_for_batch_size && rqueue.size() > 0)) &&
    next_pp_seqno + 1 <= last_executed + congestion_window &&
    next_pp_seqno + 1 <= max_out + last_stable && has_complete_new_view() &&
    !state.in_fetch_state())
  {
    btimer->stop();
    nbreqs += rqueue.size();
    nbrounds++;

    // Create new pre_prepare message for set of requests
    // in rqueue, log message and multicast the pre_prepare.
    next_pp_seqno++;
    LOG_TRACE << "creating pre prepare with seqno: " << next_pp_seqno
              << std::endl;
    size_t requests_in_batch;
    ByzInfo info;
    Pre_prepare* pp =
      new Pre_prepare(view(), next_pp_seqno, rqueue, requests_in_batch);
    if (execute_tentative(pp, info))
    {
      // TODO: should make code match my proof with request removed
      // only when executed rather than removing them from rqueue when the
      // pre-prepare is constructed.
      LOG_DEBUG << "adding to plog from pre prepare: " << next_pp_seqno
                << std::endl;
      pp->set_merkle_roots_and_ctx(
        info.full_state_merkle_root,
        info.replicated_state_merkle_root,
        info.ctx);
      pp->set_digest(signed_version.load());
      plog.fetch(next_pp_seqno).add_mine(pp);

      requests_per_batch.insert({next_pp_seqno, requests_in_batch});

      if (ledger_writer)
      {
        ledger_writer->write_pre_prepare(pp);
      }

      if (node->f() > 0)
      {
        send(pp, All_replicas);
      }
      else
      {
        send_prepare(next_pp_seqno, info);
      }
    }
    else
    {
      LOG_INFO
        << "Failed to do tentative execution at send_pre_prepare next_pp_seqno "
        << next_pp_seqno << " last_tentative " << last_tentative_execute
        << " last_executed " << last_executed << " last_stable " << last_stable
        << std::endl;
      next_pp_seqno--;
      delete pp;
    }
  }

  if (rqueue.size() > 0)
  {
    btimer->restart();
  }

  if (!(rqueue.size() == 0 ||
        (rqueue.size() != 0 &&
         (btimer->get_state() == ITimer::State::running ||
          do_not_wait_for_batch_size))))
  {
    LOG_INFO << "req_size:" << rqueue.size()
             << ", btimer_state:" << btimer->get_state() << ", do_not_wait:"
             << (do_not_wait_for_batch_size ? "true" : "false") << std::endl;
    PBFT_ASSERT(false, "send_pre_prepare rqueue and btimer issue");
  }
}

template <class T>
bool Replica::in_w(T* m)
{
  const Seqno offset = m->seqno() - last_stable;

  if (offset > 0 && offset <= max_out)
  {
    return true;
  }

  if (offset > max_out && m->verify())
  {
    // Send status message to obtain missing messages. This works as a
    // negative ack.
    send_status();
  }

  return false;
}

template <class T>
bool Replica::in_wv(T* m)
{
  const Seqno offset = m->seqno() - last_stable;

  if (offset > 0 && offset <= max_out && m->view() == view())
  {
    return true;
  }

  if (m->view() > view() || offset > max_out)
  {
    // Send status message to obtain missing messages. This works as a
    // negative ack.
    send_status();
  }

  return false;
}

void Replica::handle(Pre_prepare* m)
{
  const Seqno ms = m->seqno();
  Byz_buffer b;

  b.contents = m->choices(b.size);

  LOG_TRACE << "Received pre prepare with seqno: " << ms
            << ", in_wv:" << (in_wv(m) ? "true" : "false")
            << ", low_bound:" << low_bound << ", has complete_new_view:"
            << (has_complete_new_view() ? "true" : "false") << std::endl;

  if (in_wv(m) && ms > low_bound && has_complete_new_view())
  {
    LOG_TRACE << "processing pre prepare with seqno: " << ms << std::endl;
    Prepared_cert& pc = plog.fetch(ms);

    // Only accept message if we never accepted another pre-prepare
    // for the same view and sequence number and the message is valid.
    if (pc.add(m))
    {
      send_prepare(ms);
    }
    return;
  }

  if (!has_complete_new_view())
  {
    // This may be an old pre-prepare that replica needs to complete
    // a view-change.
    vi.add_missing(m);
    return;
  }
  delete m;
}

void Replica::send_prepare(Seqno seqno, std::optional<ByzInfo> byz_info)
{
  while (plog.within_range(seqno))
  {
    Prepared_cert& pc = plog.fetch(seqno);

    if (pc.my_prepare() == 0 && pc.is_pp_complete())
    {
      bool send_only_to_self = (f() == 0);
      // Send prepare to all replicas and log it.
      Pre_prepare* pp = pc.pre_prepare();
      ByzInfo info;
      if (byz_info.has_value())
      {
        info = byz_info.value();
      }
      else
      {
        if (!execute_tentative(pp, info))
        {
          break;
        }
      }

      // TODO: fix this check
      // https://github.com/microsoft/CCF/issues/357
      if (!compare_execution_results(info, pp))
      {
        break;
      }

      if (ledger_writer && !is_primary())
      {
        ledger_writer->write_pre_prepare(pp);
      }

      Prepare* p =
        new Prepare(v, pp->seqno(), pp->digest(), nullptr, pp->is_signed());
      int send_node_id = (send_only_to_self ? node_id : All_replicas);
      send(p, send_node_id);
      pc.add_mine(p);
      LOG_DEBUG << "added to pc in prepare: " << pp->seqno() << std::endl;

      if (pc.is_complete())
      {
        LOG_TRACE << "pc is complete for seqno: " << seqno
                  << " and sending commit" << std::endl;
        send_commit(seqno, send_node_id == node_id);
      }
      seqno++;
    }
    else
    {
      break;
    }
  }
}

void Replica::send_commit(Seqno s, bool send_only_to_self)
{
  size_t before_f = f();
  // Executing request before sending commit improves performance
  // for null requests. May not be true in general.
  if (s == last_executed + 1)
  {
    execute_prepared();
  }

  Commit* c = new Commit(view(), s);
  int send_node_id = (send_only_to_self ? node_id : All_replicas);
  send(c, send_node_id);

  if (s > last_prepared)
  {
    last_prepared = s;
  }

  Certificate<Commit>& cs = clog.fetch(s);
  if ((cs.add_mine(c) && cs.is_complete()) || (before_f == 0))
  {
    LOG_DEBUG << "calling execute committed from send_commit seqno: " << s
              << std::endl;
    execute_committed(before_f == 0);

    if (before_f == 0 && f() != 0)
    {
      Network_open no(Node::id());
      send(&no, primary());
    }
  }
}

void Replica::handle(Prepare* m)
{
  const Seqno ms = m->seqno();
  // Only accept prepare messages that are not sent by the primary for
  // current view.
  if (
    in_wv(m) && ms > low_bound && primary() != m->id() &&
    has_complete_new_view())
  {
    LOG_TRACE << "handle prepare for seqno: " << ms << std::endl;
    Prepared_cert& ps = plog.fetch(ms);
    if (ps.add(m) && ps.is_complete())
    {
      if (ledger_writer)
      {
        ledger_writer->write_prepare(ps, ms);
      }

      send_commit(ms, f() == 0);
    }
    return;
  }

  if (m->is_proof() && !has_complete_new_view())
  {
    // This may be an prepare sent to prove the authenticity of a
    // request to complete a view-change.
    vi.add_missing(m);
    return;
  }

  delete m;
  return;
}

void Replica::handle(Commit* m)
{
  const Seqno ms = m->seqno();

  // Only accept messages with the current view.  TODO: change to
  // accept commits from older views as in proof.
  if (in_wv(m) && ms > low_bound)
  {
    LOG_TRACE << "handle commit for seqno: " << m->seqno() << ", id:" << m->id()
              << std::endl;
    Certificate<Commit>& cs = clog.fetch(m->seqno());
    if (cs.add(m) && cs.is_complete())
    {
      LOG_DEBUG << "calling execute committed from handle commit for seqno: "
                << ms << std::endl;
      execute_committed();
    }
    return;
  }
  delete m;
  return;
}

void Replica::handle(Checkpoint* m)
{
  const Seqno ms = m->seqno();
  if (ms <= last_stable)
  {
    // stale checkpoint message
    delete m;
    return;
  }

  if (ms <= last_stable + max_out)
  {
    // Checkpoint is within my window.
    const bool m_stable = m->stable();
    Certificate<Checkpoint>& cs = elog.fetch(ms);
    // cs.add calls m->verify
    if (cs.add(m) && cs.mine() && cs.is_complete())
    {
      // I have enough Checkpoint messages for m->seqno() to make it stable.
      // Truncate logs, discard older stable state versions.
      PBFT_ASSERT(
        ms <= last_executed && ms <= last_tentative_execute, "Invalid state");
      mark_stable(ms, true);
      return;
    }

    if (m_stable && last_executed < ms)
    {
      // Checkpoint is stable and it is above my last_executed.
      // This may signal that messages I missed were garbage collected and I
      // should fetch the state.
      if (clog.within_range(last_executed))
      {
        Time t = 0;
        clog.fetch(last_executed).mine(t);
        // If the commit message for last_executed was sent sufficently long
        // ago, and at least f+1 replicas have reached the checkpoint with the
        // same digest, fetch state.
        if (
          cs.num_correct() > f() &&
          diff_time(ITimer::current_time(), t) > 5 * ITimer::length_100_ms())
        {
          fetch_state_outside_view_change();
        }
      }
    }

    return;
  }

  // Checkpoint message above my window.
  if (!m->stable())
  {
    // Send status message to obtain missing messages. This works as a
    // negative ack.
    send_status();
    delete m;
    return;
  }

  // Stable checkpoint message above my window.
  auto it = stable_checkpoints.find(m->id());
  if (it == stable_checkpoints.end() || it->second->seqno() < ms)
  {
    stable_checkpoints.insert_or_assign(
      m->id(), std::unique_ptr<Checkpoint>(m));
    if (stable_checkpoints.size() > f())
    {
      fetch_state_outside_view_change();
    }
    return;
  }

  delete m;
}

void Replica::fetch_state_outside_view_change()
{
  if (last_tentative_execute > last_executed)
  {
    // Rollback to last checkpoint
    PBFT_ASSERT(!state.in_fetch_state(), "Invalid state");
    LOG_INFO << "Rolling back before start_fetch last_tentative_execute: "
             << last_tentative_execute << " last_executed: " << last_executed
             << std::endl;
    Seqno rc = state.rollback(last_executed);
    LOG_INFO << " rolled back to :" << rc << std::endl;
    last_tentative_execute = last_executed = rc;
  }

  // Stop view change timer while fetching state. It is restarted
  // in new state when the fetch ends.
  vtimer->stop();
#ifdef DEBUG_SLOW
  debug_slow_timer->stop();
#endif
  state.start_fetch(last_executed);
}

void Replica::register_reply_handler(reply_handler_cb cb, void* ctx)
{
  rep_cb = cb;
  rep_cb_ctx = ctx;
}

void Replica::register_global_commit(global_commit_handler_cb cb, void* ctx)
{
  global_commit_cb = cb;
  global_commit_ctx = ctx;
}

void Replica::handle(Reply* m)
{
  if (rep_cb != nullptr)
  {
    rep_cb(m, rep_cb_ctx);
    return;
  }
  delete m;
}

size_t Replica::num_correct_replicas() const
{
  return Node::num_correct_replicas();
}

size_t Replica::f() const
{
  return Node::f();
}

void Replica::set_f(ccf::NodeId f)
{
  if (max_faulty == 0 && f > 0)
  {
    if (Node::id() == primary())
    {
      LOG_INFO << "Waiting for network to open" << std::endl;
      wait_for_network_to_open = true;
    }

    rqueue.clear();
  }

  Node::set_f(f);
}

void Replica::emit_signature_on_next_pp(int64_t version)
{
  sign_next = true;
  signed_version = version;
}

View Replica::view() const
{
  return Node::view();
}

bool Replica::is_primary() const
{
  return primary() == Node::id();
}

int Replica::primary() const
{
  return Node::primary();
}

int Replica::primary(View view) const
{
  return Node::primary(view);
}

void Replica::send(Message* m, int i)
{
  return Node::send(m, i);
}

Seqno Replica::get_last_executed() const
{
  return last_executed;
}

int Replica::my_id() const
{
  return Node::id();
}

void Replica::handle(Status* m)
{
  static const int max_ret_bytes = 65536;

  if (qs == 0)
  {
    Time current;
    Time t_sent = 0;
    current = ITimer::current_time();
    std::shared_ptr<Principal> p = node->get_principal(m->id());
    if (!p)
    {
      return;
    }

    // Retransmit messages that the sender is missing.
    if (last_stable > m->last_stable() + max_out)
    {
      // Node is so out-of-date that it will not accept any
      // pre-prepare/prepare/commmit messages in my log.
      // Send a stable checkpoint message for my stable checkpoint.
      Checkpoint* c = elog.fetch(last_stable).mine(t_sent);
      if (c != 0 && c->stable())
      {
        retransmit(c, current, t_sent, p.get());
      }
      delete m;
      return;
    }

    // Retransmit any checkpoints that the sender may be missing.
    int max = std::min(last_stable, m->last_stable()) + max_out;
    int min = std::max(last_stable, m->last_stable() + 1);
    for (Seqno n = min; n <= max; n++)
    {
      if (n % checkpoint_interval == 0)
      {
        Checkpoint* c = elog.fetch(n).mine(t_sent);
        if (c != 0)
        {
          retransmit(c, current, t_sent, p.get());
          PBFT_ASSERT(n == last_stable || !c->stable(), "Invalid state");
        }
      }
    }

    if (m->view() < v)
    {
      // Retransmit my latest view-change message
      View_change* vc = vi.my_view_change(t_sent);
      if (vc != 0)
      {
        retransmit(vc, current, t_sent, p.get());
      }
      delete m;
      return;
    }

    if (m->view() == v)
    {
      if (m->has_nv_info())
      {
        min = std::max(last_stable + 1, m->last_executed() + 1);
        for (Seqno n = min; n <= max; n++)
        {
          if (m->is_committed(n))
          {
            // No need for retransmission of commit or pre-prepare/prepare
            // message.
            continue;
          }

          Commit* c = clog.fetch(n).mine(t_sent);
          if (c != 0)
          {
            retransmit(c, current, t_sent, p.get());
          }

          if (m->is_prepared(n))
          {
            // No need for retransmission of pre-prepare/prepare message.
            continue;
          }

          // If I have a pre-prepare/prepare send it, provided I have sent
          // a pre-prepare/prepare for view v.
          if (primary() == node_id)
          {
            Pre_prepare* pp = plog.fetch(n).my_pre_prepare(t_sent);
            if (pp != 0)
            {
              retransmit(pp, current, t_sent, p.get());
            }
          }
          else
          {
            Prepare* pr = plog.fetch(n).my_prepare(t_sent);
            if (pr != 0)
            {
              retransmit(pr, current, t_sent, p.get());
            }
          }
        }

        if (id() == primary())
        {
          // For now only primary retransmits big requests.
          Status::BRS_iter gen(m);

          int count = 0;
          Seqno ppn;
          BR_map mrmap;
          while (gen.get(ppn, mrmap) && count <= max_ret_bytes)
          {
            if (plog.within_range(ppn))
            {
              Pre_prepare_info::BRS_iter gen(
                plog.fetch(ppn).prep_info(), mrmap);
              Request* r;
              while (gen.get(r))
              {
                INCR_OP(message_counts_retransmitted[m->tag()]);
                send(r, m->id());
                count += r->size();
              }
            }
          }
        }
      }
      else
      {
        if (!m->has_vc(node_id))
        {
          // p does not have my view-change: send it.
          View_change* vc = vi.my_view_change(t_sent);
          PBFT_ASSERT(vc != 0, "Invalid state");
          retransmit(vc, current, t_sent, p.get());
        }

        if (!m->has_nv_m())
        {
          if (primary(v) == node_id && vi.has_complete_new_view(v))
          {
            // p does not have new-view message and I am primary: send it
            New_view* nv = vi.my_new_view(t_sent);
            if (nv != 0)
            {
              retransmit(nv, current, t_sent, p.get());
            }
          }
        }
        else
        {
          if (primary(v) == node_id && vi.has_complete_new_view(v))
          {
#ifdef USE_PKEY_VIEW_CHANGES
            New_view* nv = vi.my_new_view(t_sent);
            if (nv != 0)
            {
              for (int i = 0; i < num_replicas; i++)
              {
                if (!m->has_vc(i) && nv->view_change(i))
                {
                  retransmit(vi.view_change(i), current, t_sent, p.get());
                }
              }
            }
#else
            // TODO: Send any view-change messages that p may be missing
            // that are referred to by the new-view message.  This may
            // be important if the sender of the original message is
            // faulty.
#endif
          }
#ifndef USE_PKEY_VIEW_CHANGES
          else
          {
            // Send any view-change acks p may be missing.
            for (int i = 0; i < num_replicas; i++)
            {
              if (m->id() == i)
              {
                continue;
              }
              View_change_ack* vca = vi.my_vc_ack(i);
              if (vca && !m->has_vc(i))
              {
                // View-change acks are not being authenticated
                retransmit(vca, current, 0, p.get());
              }
            }
          }
#endif

          // Send any pre-prepares that p may be missing and any proofs
          // of authenticity for associated requests.
          Status::PPS_iter gen(m);

          int count = 0;
          Seqno ppn;
          View ppv;
          bool ppp;
          BR_map mrmap;
          while (gen.get(ppv, ppn, mrmap, ppp))
          {
            Pre_prepare* pp = 0;
            if (m->id() == primary(v))
            {
              pp = vi.pre_prepare(ppn, ppv);
            }
            else
            {
              if (primary(v) == id() && plog.within_range(ppn))
              {
                pp = plog.fetch(ppn).pre_prepare();
              }
            }

            if (pp)
            {
              retransmit(pp, current, 0, p.get());

              if (count < max_ret_bytes && !mrmap.all())
              {
                Pre_prepare_info pp_info;
                pp_info.add_complete(pp);

                Pre_prepare_info::BRS_iter gen(&pp_info, mrmap);
                Request* r;
                while (gen.get(r))
                {
                  send(r, m->id());
                  count += r->size();
                }
                pp_info.zero(); // Make sure pp does not get deallocated
              }
            }

            if (ppp)
            {
              vi.send_proofs(ppn, ppv, m->id());
            }
          }
        }
      }
    }
  }
  else
  {}

  delete m;
}

void Replica::handle(View_change* m)
{
  LOG_INFO << "Received view change for " << m->view() << " from " << m->id()
           << ", v:" << v << std::endl;

  if (m->id() == primary() && m->view() > v)
  {
    // "m" was sent by the primary for v and has a view number
    // higher than v: move to the next view.
    send_view_change();
  }
  vi.add(std::unique_ptr<View_change>(m));

  // TODO: memoize maxv and avoid this computation if it cannot change i.e.
  // m->view() <= last maxv. This also holds for the next check.
  View maxv = vi.max_view();
  if (maxv > v)
  {
    // Replica has at least f+1 view-changes with a view number
    // greater than or equal to maxv: change to view maxv.
    v = maxv - 1;
    vc_recovering = true;
    send_view_change();
  }

  if (limbo && primary() != node_id)
  {
    maxv = vi.max_maj_view();
    PBFT_ASSERT(maxv <= v, "Invalid state");

    if (maxv == v)
    {
      // Replica now has at least 2f+1 view-change messages with view  greater
      // than or equal to "v"

      // Start timer to ensure we move to another view if we do not
      // receive the new-view message for "v".
      LOG_INFO << "Starting view change timer for view " << v << "\n";
      vtimer->restart();
      limbo = false;
      vc_recovering = true;
    }
  }
}

void Replica::handle(New_view* m)
{
  LOG_INFO << "Received new view for " << m->view() << " from " << m->id()
           << std::endl;
  vi.add(m);
}

void Replica::handle(View_change_ack* m)
{
  LOG_INFO << "Received view change ack from " << m->id()
           << " for view change message for " << m->view() << " from "
           << m->vc_id() << "\n";
  vi.add(m);
}

void Replica::send_view_change()
{
  LOG_INFO << "Before sending view change for " << v + 1 << std::endl;
  if (cur_primary == node_id)
  {
    vi.dump_state(std::cout);
  }

  // Move to next view.
  v++;
  cur_primary = v % num_replicas;
  limbo = true;
  vtimer->stop(); // stop timer if it is still running
  ntimer->restop();

  LOG_INFO << "send_view_change last_executed: " << last_executed
           << " last_tentative_execute: " << last_tentative_execute
           << " last_stable: " << last_stable
           << " last_prepared: " << last_prepared
           << "next_pp_seqno: " << next_pp_seqno << std::endl;
  LOG_INFO << "plog:" << std::endl;
  plog.dump_state(std::cout);
  LOG_INFO << "clog:" << std::endl;
  clog.dump_state(std::cout);
  LOG_INFO << "elog:" << std::endl;
  elog.dump_state(std::cout);

#ifndef ENFORCE_EXACTLY_ONCE
  replies.clear();
#endif

  if (last_tentative_execute > last_executed)
  {
    // Rollback to last checkpoint
    PBFT_ASSERT(!state.in_fetch_state(), "Invalid state");
    Seqno rc = state.rollback(last_executed);
    LOG_INFO << "Rolled back in view change to seqno " << rc
             << " last_executed was " << last_executed
             << " last_tentative_execute was " << last_tentative_execute
             << std::endl;
    last_tentative_execute = last_executed = rc;
  }

  last_prepared = last_executed;

  for (Seqno i = last_stable + 1; i <= last_stable + max_out; i++)
  {
    Prepared_cert& pc = plog.fetch(i);
    Certificate<Commit>& cc = clog.fetch(i);

    if (pc.is_complete())
    {
      vi.add_complete(pc.rem_pre_prepare());
    }
    else
    {
      Prepare* p = pc.my_prepare();
      if (p != 0)
      {
        vi.add_incomplete(i, p->digest());
      }
      else
      {
        Pre_prepare* pp = pc.my_pre_prepare();
        if (pp != 0)
        {
          vi.add_incomplete(i, pp->digest());
        }
      }
    }

    pc.clear();
    cc.clear();
    // TODO: Could remember info about committed requests for efficiency.
  }

  // Create and send view-change message.
  vi.view_change(v, last_executed, &state);

  // Write the view change proof to the ledger
#ifdef SIGN_BATCH
  write_view_change_to_ledger();
#endif
}

void Replica::write_view_change_to_ledger()
{
  if (!ledger_writer)
  {
    return;
  }

  auto principals = get_principals();
  for (const auto& it : *principals)
  {
    const std::shared_ptr<Principal>& p = it.second;
    if (p == nullptr || !p->is_replica())
    {
      continue;
    }
    View_change* vc = vi.view_change(p->pid());
    if (vc == nullptr)
    {
      continue;
    }

    ledger_writer->write_view_change(vc);
  }
}

void Replica::handle(New_principal* m)
{
  LOG_INFO << "recevied new message to add principal, id:" << m->id()
           << std::endl;

  PrincipalInfo info{m->id(),
                     m->port(),
                     m->ip(),
                     m->pubk_sig(),
                     m->pubk_enc(),
                     m->host_name(),
                     m->is_replica()};

  node->add_principal(info);
}

void Replica::handle(Network_open* m)
{
  std::shared_ptr<Principal> p = get_principal(m->id());
  if (p == nullptr)
  {
    LOG_FAIL << "Received network open from unknown principal, id:" << m->id()
             << std::endl;
  }

  if (p->received_network_open_msg())
  {
    LOG_FAIL << "Received network open from, id:" << m->id() << "already"
             << std::endl;
  }

  LOG_INFO << "Received network open from, id:" << m->id() << std::endl;

  p->set_received_network_open_msg();

  uint32_t num_open = 0;
  auto principals = get_principals();
  for (const auto& it : *principals)
  {
    if (it.second->received_network_open_msg())
    {
      ++num_open;
    }
  }

  if (num_open == principals->size())
  {
    LOG_INFO << "Finished waiting for machines to network open. "
             << "starting to process requests" << std::endl;
    wait_for_network_to_open = false;
    send_pre_prepare();
  }

  delete m;
}

void Replica::process_new_view(Seqno min, Digest d, Seqno max, Seqno ms)
{
  PBFT_ASSERT(ms >= 0 && ms <= min, "Invalid state");
  LOG_INFO << "Process new view: " << v << " min: " << min << " max: " << max
           << " ms: " << ms << " last_stable: " << last_stable
           << " last_executed: " << last_executed
           << " last_tentative_execute: " << last_tentative_execute
           << std::endl;

  rqueue.clear();
  vtimer->restop();
  limbo = false;
  vc_recovering = true;

  if (primary(v) == id())
  {
    New_view* nv = vi.my_new_view();
    LOG_INFO << "Sending new view for " << nv->view() << std::endl;
    send(nv, All_replicas);
  }

  next_pp_seqno = max - 1;

  if (ms > last_stable)
  {
    // Call mark_stable to ensure there is space for the pre-prepares
    // and prepares that are inserted in the log below.
    mark_stable(ms, last_executed >= ms);
  }

  if (last_stable > min)
  {
    min = last_stable;
  }
  low_bound = min;

  has_nv_state = (last_executed >= min);

  // Update pre-prepare/prepare logs.
  PBFT_ASSERT(min >= last_stable, "Invalid state");
  PBFT_ASSERT(
    max <= min + 1 || max - last_stable - 1 <= max_out, "Invalid state");
  for (Seqno i = min + 1; i < max; i++)
  {
    Digest d;
    Pre_prepare* pp = vi.fetch_request(i, d);
    Prepared_cert& pc = plog.fetch(i);
    PBFT_ASSERT(pp != 0 && pp->digest() == d, "Invalid state");

    if (primary() == id())
    {
      ByzInfo info;
      pc.add_mine(pp);
      if (ledger_writer)
      {
        ledger_writer->write_pre_prepare(pp);
      }
      execute_tentative(pp, info);
    }
    else
    {
      ByzInfo info;
      pc.add_old(pp);
      if (ledger_writer)
      {
        ledger_writer->write_pre_prepare(pp);
      }
      execute_tentative(pp, info);

      Prepare* p = new Prepare(v, i, d, nullptr, pp->is_signed());
      pc.add_mine(p);
      send(p, All_replicas);
    }

    if (i <= last_executed || pc.is_complete())
    {
      send_commit(i);
    }
  }

  if (primary() == id())
  {
    PBFT_ASSERT(last_tentative_execute <= next_pp_seqno, "Invalid state");

    send_pre_prepare();
    ntimer->start();
  }

  if (!has_nv_state)
  {
#ifdef DEBUG_SLOW
    debug_slow_timer->stop();
#endif
    LOG_INFO << "fetching state in process new view v: " << v << std::endl;
    state.start_fetch(last_executed, min, &d, min <= ms);
  }
  else
  {
    PBFT_ASSERT(last_executed >= last_stable, "Invalid state");

    // Execute any buffered read-only requests
    for (Request* m = ro_rqueue.remove(); m != 0; m = ro_rqueue.remove())
    {
      execute_read_only(m);
      delete m;
    }
  }

  if (primary() != id() && rqueue.size() > 0)
  {
    start_vtimer_if_request_waiting();
  }
  LOG_INFO << "Done with process new view " << v << std::endl;
}

Pre_prepare* Replica::prepared_pre_prepare(Seqno n)
{
  Prepared_cert& pc = plog.fetch(n);
  if (pc.is_complete())
  {
    return pc.pre_prepare();
  }
  return 0;
}

Pre_prepare* Replica::committed(Seqno s, bool was_f_0)
{
  // TODO: This is correct but too conservative: fix to handle case
  // where commit and prepare are not in same view; and to allow
  // commits without prepared requests, i.e., only with the
  // pre-prepare.
  Pre_prepare* pp = prepared_pre_prepare(s);
  if (clog.fetch(s).is_complete() || was_f_0)
  {
    return pp;
  }
  return 0;
}

bool Replica::execute_read_only(Request* request)
{
  // JC: won't execute read-only if there's a current tentative execution
  // this probably isn't necessary if clients wait for 2f+1 RO responses
  if (
    last_tentative_execute == last_executed && !state.in_fetch_state() &&
    !state.in_check_state())
  {
    // Create a new Reply message. Replies to read-only requests always
    // indicate that they were executed at sequence number zero because
    // they may execute at different sequence numbers provided the client
    // gets enough matching replies and the sequence numbers must match.
    Reply* rep = new Reply(view(), request->request_id(), 0, node_id);

    // Obtain "in" and "out" buffers to call exec_command
    Byz_req inb;
    Byz_rep outb;

    inb.contents = request->command(inb.size);
    outb.contents = rep->store_reply(outb.size);

    // Execute command.
    int client_id = request->client_id();
    std::shared_ptr<Principal> cp = get_principal(client_id);
    ByzInfo info;
    int error = exec_command(&inb, &outb, 0, client_id, true, 0, info);
    right_pad_contents(outb);

    if (!error)
    {
      // Finish constructing the reply and send it.
      rep->authenticate(cp.get(), outb.size, true);
      if (
        outb.size < SMALL_REPLY_THRESHOLD || request->replier() == node_id ||
        request->replier() < 0)
      {
        // Send full reply.
        send(rep, client_id);
      }
      else
      {
        // Send empty reply.
        Reply empty(
          view(),
          request->request_id(),
          0,
          node_id,
          rep->digest(),
          cp.get(),
          true);
        send(&empty, client_id);
      }
    }

    delete rep;
    return true;
  }
  else
  {
    return false;
  }
}

void Replica::execute_prepared(bool committed)
{
#ifndef ENFORCE_EXACTLY_ONCE
  if (committed)
  {
    return;
  }
#endif

  Pre_prepare* pp = prepared_pre_prepare(last_executed + 1);

  if (pp && pp->view() == view())
  {
    // Iterate over the requests in the message, sending replies
    // for each of them
    Pre_prepare::Requests_iter iter(pp);
    Request request;

    while (iter.get(request))
    {
      int client_id = request.client_id();
      Request_id rid = request.request_id();

#ifdef ENFORCE_EXACTLY_ONCE
      Reply* reply = replies.reply(client_id);
      PBFT_ASSERT(reply != nullptr, "Reply not in replies");
      bool reply_is_committed = replies.is_committed(client_id);
#else
      Reply* reply = replies.reply(client_id, rid, last_executed + 1);
      bool reply_is_committed = false;
      if (reply == nullptr)
      {
        continue;
      }
#endif
      // int reply_size = reply->size();

      if (reply->request_id() == rid && reply_is_committed == committed)
      {
#ifdef USE_DIGEST_REPLIES_OPTIMIZATION
        if (
          reply_size >= SMALL_REPLY_THRESHOLD && request.replier() != id() &&
          request.replier() >= 0)
        {
          // Send empty reply.
          Reply empty(
            view(),
            rid,
            last_executed + 1,
            node_id,
            reply->digest(),
            get_principal(client_id),
            !committed);

          send(&empty, client_id);
        }
        else
#endif
        {
          // Send full reply.
#ifdef ENFORCE_EXACTLY_ONCE
          replies.send_reply(client_id, view(), id(), !committed);
#else
          replies.send_reply(client_id, rid, last_executed + 1, view(), id());
#endif
        }
      }
    }

    if (global_commit_cb != nullptr && pp->is_signed())
    {
      LOG_TRACE_FMT(
        "Global_commit: {}, signed_version: {}",
        pp->get_ctx(),
        global_commit_ctx);

      global_commit_cb(pp->get_ctx(), pp->view(), global_commit_ctx);
      signed_version = 0;
    }
  }
}

bool Replica::execute_tentative(Pre_prepare* pp, ByzInfo& info)
{
  LOG_DEBUG << "in execute tentative: " << pp->seqno() << std::endl;
  if (
    pp->seqno() == last_tentative_execute + 1 && !state.in_fetch_state() &&
    !state.in_check_state() && has_complete_new_view())
  {
    last_tentative_execute = last_tentative_execute + 1;
    LOG_TRACE << "in execute tentative with last_tentative_execute: "
              << last_tentative_execute
              << " and last_executed: " << last_executed << std::endl;

    // Iterate over the requests in the message, calling execute for
    // each of them.
    Pre_prepare::Requests_iter iter(pp);
    Request request;
    int64_t max_local_commit_value = INT64_MIN;

    while (iter.get(request))
    {
      int client_id = request.client_id();

#ifdef ENFORCE_EXACTLY_ONCE
      if (replies.req_id(client_id) >= request.request_id())
      {
        // Request has already been executed and we have the reply to
        // the request. Resend reply and don't execute request
        // to ensure idempotence.
        INCR_OP(message_counts_retransmitted[Reply_tag]);
        replies.send_reply(
          client_id, view(), id(), !replies.is_committed(client_id));
        LOG_DEBUG << "Sending from tentative exec: " << pp->seqno()
                  << " from client: " << client_id
                  << " rid: " << request.request_id() << std::endl;
        continue;
      }
#endif

      // Obtain "in" and "out" buffers to call exec_command
      Byz_req inb;
      Byz_rep outb;
      Byz_buffer non_det;
      inb.contents = request.command(inb.size);

#ifdef ENFORCE_EXACTLY_ONCE
      outb.contents = replies.new_reply(client_id);
#else
      outb.contents = replies.new_reply(
        client_id, request.request_id(), last_tentative_execute);
      if (outb.contents == nullptr)
      {
        // to defend against a malicious primary that adds the same request id
        // twice to the same batch
        continue;
      }
#endif
      outb.size = replies.new_reply_size();
      non_det.contents = pp->choices(non_det.size);
      // Execute command in a regular request.
      replies.count_request();
      LOG_TRACE << "before exec command with seqno: " << pp->seqno()
                << std::endl;
      exec_command(
        &inb,
        &outb,
        &non_det,
        client_id,
        false,
        replies.total_requests_processed(),
        info);
      right_pad_contents(outb);
      // Finish constructing the reply.
      LOG_DEBUG << "Executed from tentative exec: " << pp->seqno()
                << " from client: " << client_id
                << " rid: " << request.request_id()
                << " commit_id: " << info.ctx << std::endl;

      if (info.ctx > max_local_commit_value)
      {
        max_local_commit_value = info.ctx;
      }

      info.ctx = max_local_commit_value;
#ifdef ENFORCE_EXACTLY_ONCE
      replies.end_reply(client_id, request.request_id(), outb.size);
#else
      replies.end_reply(
        client_id, request.request_id(), last_tentative_execute, outb.size);
#endif
    }
    LOG_DEBUG << "Executed from tentative exec: " << pp->seqno()
              << " rid: " << request.request_id() << " commit_id: " << info.ctx
              << std::endl;

    if (last_tentative_execute % checkpoint_interval == 0)
    {
      state.checkpoint(last_tentative_execute);
    }
    return true;
  }
  return false;
}

void Replica::create_recovery_reply(
  int client_id, int last_tentative_execute, Byz_rep& outb)
{
  max_rec_n = last_tentative_execute;
  // Reply includes sequence number where request was executed.
  outb.size = sizeof(last_tentative_execute);
  memcpy(outb.contents, &last_tentative_execute, outb.size);
}

void Replica::right_pad_contents(Byz_rep& outb)
{
  if (outb.size % ALIGNMENT_BYTES)
  {
    for (int i = 0; i < ALIGNMENT_BYTES - (outb.size % ALIGNMENT_BYTES); i++)
    {
      outb.contents[outb.size + i] = 0;
    }
  }
}

void Replica::execute_committed(bool was_f_0)
{
  if (
    !state.in_fetch_state() && !state.in_check_state() &&
    has_complete_new_view())
  {
    while (1)
    {
      if (last_executed >= last_stable + max_out || last_executed < last_stable)
      {
        return;
      }

      Pre_prepare* pp = committed(last_executed + 1, was_f_0);

      if (pp && pp->view() == view())
      {
        // Can execute the requests in the message with sequence number
        // last_executed+1.
        if (last_executed + 1 > last_tentative_execute)
        {
          ByzInfo info;
          auto executed_ok = execute_tentative(pp, info);
          PBFT_ASSERT(
            executed_ok,
            "tentative execution while executing committed failed");
          PBFT_ASSERT(
            last_executed + 1 == last_tentative_execute,
            "last tentative did not advance with last executed");
          LOG_DEBUG << "Executed tentative in committed for: " << pp->seqno()
                    << " execution result true or false: " << executed_ok
                    << std::endl;
        }

        set_min_pre_prepare_batch_size();

        execute_prepared(true);
        last_executed = last_executed + 1;
        stats.last_executed = last_executed;
        PBFT_ASSERT(pp->seqno() == last_executed, "Invalid execution");

#ifdef DEBUG_SLOW
        if (pp->num_big_reqs() > 0)
        {
          debug_slow_timer->stop();
          debug_slow_timer->start();
        }
#endif

        // Execute any buffered read-only requests
        for (Request* m = ro_rqueue.remove(); m != 0; m = ro_rqueue.remove())
        {
          execute_read_only(m);
          delete m;
        }

        // Iterate over the requests in the message, marking the saved replies
        // as committed (i.e., non-tentative for each of them).
        Pre_prepare::Requests_iter iter(pp);
        Request request;
        while (iter.get(request))
        {
          int client_id = request.client_id();

#ifdef ENFORCE_EXACTLY_ONCE
          replies.commit_reply(client_id);
#endif

          // Remove the request from rqueue if present.
          if (rqueue.remove(client_id, request.request_id()))
          {
            vtimer->stop();
          }
        }

        // Send and log Checkpoint message for the new state if needed.
        if (last_executed % checkpoint_interval == 0)
        {
          Digest d_state;
          state.digest(last_executed, d_state);
          Checkpoint* e = new Checkpoint(last_executed, d_state);
          Certificate<Checkpoint>& cc = elog.fetch(last_executed);
          cc.add_mine(e);

          send(e, All_replicas);

          if (cc.is_complete())
          {
            mark_stable(last_executed, true);
          }
        }
      }
      else
      {
        // No more requests to execute at this point.
        break;
      }
    }

    if (rqueue.size() > 0)
    {
      if (primary() == node_id)
      {
        // Send a pre-prepare with any buffered requests
        send_pre_prepare();
      }
      else
      {
        // If I am not the primary and have pending requests restart the
        // timer.
        start_vtimer_if_request_waiting();
      }
    }
  }
}

void Replica::set_min_pre_prepare_batch_size()
{
  // Find the batch that was completed, work out the number of requests
  // in said batch and remove this batch from history
  auto it = requests_per_batch.find(last_executed + 1);
  uint64_t request_count = 0;
  if (it != requests_per_batch.end())
  {
    request_count = it->second;
    requests_per_batch.erase(it);
  }

  for (auto it : requests_per_batch)
  {
    request_count += it.second;
  }
  request_count += rqueue.size();

  // If there are pending or executed requests in this batch
  // and if so save this info to history
  if (request_count > 0)
  {
    if (max_pending_reqs.size() > num_look_back_to_set_batch_size)
    {
      max_pending_reqs.pop_back();
    }
    max_pending_reqs.push_front(request_count);
  }

  // look through the history of pending requests and find the max and
  // use that to set the min batch size
  uint64_t max_max_pending_reqs = 0;
  for (auto it : max_pending_reqs)
  {
    max_max_pending_reqs = std::max(max_max_pending_reqs, it);
  }

  min_pre_prepare_batch_size =
    (max_max_pending_reqs / (congestion_window + 1) +
     max_max_pending_reqs % (congestion_window + 1));

  if (min_pre_prepare_batch_size < min_min_pre_prepare_batch_size)
  {
    min_pre_prepare_batch_size = min_min_pre_prepare_batch_size;
  }
  LOG_TRACE << "new min_pre_prepare_batch_size is: "
            << min_pre_prepare_batch_size << std::endl;
}

void Replica::new_state(Seqno c)
{
  LOG_DEBUG << "Replica got new state at c: " << c << std::endl;
  if (vi.has_complete_new_view(v) && c >= low_bound)
  {
    has_nv_state = true;
  }

#ifndef ENFORCE_EXACTLY_ONCE
  replies.clear();
#endif

#ifdef DEBUG_SLOW
  debug_slow_timer->start();
#endif

  if (c < last_stable)
  {
    LOG_INFO << "new_state c:" << c << " last_stable: " << last_stable
             << std::endl;
  }

  if (c > next_pp_seqno)
  {
    next_pp_seqno = c;
  }

  if (c > last_prepared)
  {
    last_prepared = c;
  }

  if (c > last_executed)
  {
    last_executed = last_tentative_execute = c;
    stats.last_executed = last_executed;

#ifdef ENFORCE_EXACTLY_ONCE
    if (replies.new_state(&rqueue))
    {
      vtimer->stop();
    }
#endif

    rqueue.clear();

    if (c > last_stable + max_out)
    {
      // We know that we are stable at least up to
      // the start of the max sized window that includes c.
      // Note that this moves checkpoint messages from stable_checkpoints
      // to the certificate for c in elog. It also grows the window
      // to allow accessing the log at seqno c below.
      mark_stable(
        c - max_out,
        elog.within_range(c - max_out) && elog.fetch(c - max_out).mine());
    }

    // Send checkpoint message for checkpoint "c" and
    // mark stable if appropriate
    Digest d;
    state.digest(c, d);
    Checkpoint* ck = new Checkpoint(c, d);
    auto& cert = elog.fetch(c);
    cert.add_mine(ck);

    send(ck, All_replicas);

    if (cert.is_complete())
    {
      PBFT_ASSERT(
        c <= last_executed && c <= last_tentative_execute, "Invalid state");
      mark_stable(c, true);
    }
  }

  // Check if c is known to be stable.
  int scount = 0;
  for (int i = 0; i < num_replicas; i++)
  {
    auto it = stable_checkpoints.find(i);
    if (it != stable_checkpoints.end() && it->second->seqno() >= c)
    {
      PBFT_ASSERT(it->second->stable(), "Invalid state");
      scount++;
    }
  }
  if (scount > f())
  {
    PBFT_ASSERT(
      c <= last_executed && c <= last_tentative_execute, "Invalid state");
    mark_stable(c, true);
  }

  // Execute any committed requests
  execute_committed();

  if (last_tentative_execute > next_pp_seqno)
  {
    next_pp_seqno = last_tentative_execute;
  }

  // Execute any buffered read-only requests
  for (Request* m = ro_rqueue.remove(); m != 0; m = ro_rqueue.remove())
  {
    execute_read_only(m);
    delete m;
  }

  if (rqueue.size() > 0)
  {
    if (primary() == id())
    {
      // Send pre-prepares for any buffered requests
      send_pre_prepare();
    }
    else
    {
      start_vtimer_if_request_waiting();

      // Send status to force retransmission of message we may have lost
      // because they were outside the window while we were fetching state
      send_status(true);
    }
  }
}

void Replica::mark_stable(Seqno n, bool have_state)
{
  if (n <= last_stable)
  {
    return;
  }

  last_stable = n;
  if (last_stable > low_bound)
  {
    low_bound = last_stable;
  }

  if (have_state && last_stable > last_executed)
  {
    LOG_TRACE << "mark stable, last_tentative_execute: "
              << last_tentative_execute << " last_stable: " << last_stable
              << std::endl;
    PBFT_ASSERT(last_tentative_execute < last_stable, "Invalid state");
    last_executed = last_tentative_execute = last_stable;
    stats.last_executed = last_executed;

#ifdef ENFORCE_EXACTLY_ONCE
    replies.new_state(&rqueue);
#endif

    if (last_stable > last_prepared)
    {
      last_prepared = last_stable;
    }
  }

  if (last_stable > next_pp_seqno)
  {
    next_pp_seqno = last_stable;
  }

  plog.truncate(last_stable + 1);
  clog.truncate(last_stable + 1);
  vi.mark_stable(last_stable);
  elog.truncate(last_stable);
  state.discard_checkpoints(last_stable, last_executed);
  brt.mark_stable(last_stable);

  if (have_state)
  {
    // Re-authenticate my checkpoint message to mark it as stable or
    // if I do not have one put one in and make the corresponding
    // certificate complete.
    Checkpoint* c = elog.fetch(last_stable).mine();
    if (c == 0)
    {
      Digest d_state;
      bool have_digest = state.digest(last_stable, d_state);
      auto correct_checkpoint = elog.fetch(last_stable).cvalue();
      if (!have_digest && correct_checkpoint != nullptr)
      {
        d_state = correct_checkpoint->digest();
        have_digest = true;
      }

      if (have_digest)
      {
        c = new Checkpoint(last_stable, d_state, true);
        elog.fetch(last_stable).add_mine(c);
        elog.fetch(last_stable).make_complete();
      }
    }
    else
    {
      c->re_authenticate(0, true);
    }

    try_end_recovery();
  }

  // Go over stable_checkpoints transfering any checkpoints that are now within
  // my window to elog.
  Seqno new_ls = last_stable;
  for (int i = 0; i < num_replicas; i++)
  {
    auto it = stable_checkpoints.find(i);
    if (it != stable_checkpoints.end())
    {
      Seqno cn = it->second->seqno();
      if (cn < last_stable)
      {
        stable_checkpoints.erase(it);
        continue;
      }

      if (cn <= last_stable + max_out)
      {
        Certificate<Checkpoint>& cs = elog.fetch(cn);
        cs.add(it->second.release());
        stable_checkpoints.erase(it);
        if (cs.is_complete() && cn > new_ls)
        {
          new_ls = cn;
        }
      }
    }
  }

  if (new_ls > last_stable)
  {
    if (elog.within_range(new_ls) && elog.fetch(new_ls).mine())
    {
      PBFT_ASSERT(
        last_executed >= new_ls && last_tentative_execute >= new_ls,
        "Invalid state");
      mark_stable(new_ls, true);
    }
    else
    {
      fetch_state_outside_view_change();
    }
  }

  // Try to send any Pre_prepares for any buffered requests.
  if (primary() == id())
  {
    send_pre_prepare();
  }
}

void Replica::handle(Data* m)
{
  state.handle(m);
}

void Replica::handle(Meta_data* m)
{
  state.handle(m);
}

void Replica::handle(Meta_data_d* m)
{
  state.handle(m);
}

void Replica::handle(Fetch* m)
{
  int mid = m->id();
  state.handle(m, last_stable);
}

void Replica::send_status(bool send_now)
{
  // Check how long ago we sent the last status message.
  Time cur = ITimer::current_time();
  if (send_now || diff_time(cur, last_status) > ITimer::length_100_ms())
  {
    // Only send new status message if last one was sent more
    // than 100 milliseconds ago, or the send_now flag is set
    last_status = cur;

    if (qs)
    {
      // Retransmit query stable if I am estimating last stable
      qs->re_authenticate();
      send(qs, All_replicas);
      return;
    }

    if (rr)
    {
      // Retransmit recovery request if I am waiting for one.
      send(rr, All_replicas);
    }

    // If fetching state, resend last fetch message instead of status.
    if (state.retrans_fetch(cur))
    {
      state.send_fetch(true);
      return;
    }

    Status s(
      v,
      last_stable,
      last_executed,
      has_complete_new_view(),
      vi.has_nv_message(v));

    if (has_complete_new_view())
    {
      // Set prepared and committed bitmaps correctly
      Seqno max = last_stable + max_out;
      Seqno min = std::max(last_executed, last_stable) + 1;
      for (Seqno n = min; n <= max; n++)
      {
        Prepared_cert& pc = plog.fetch(n);
        if (pc.is_complete() || state.in_check_state())
        {
          s.mark_prepared(n);
          if (clog.fetch(n).is_complete() || state.in_check_state())
          {
            s.mark_committed(n);
          }
        }
        else
        {
          // Ask for missing big requests
          if (
            !pc.is_pp_complete() && pc.pre_prepare() && pc.num_correct() >= f())
          {
            s.add_breqs(n, pc.missing_reqs());
          }
        }
      }
    }
    else
    {
      vi.set_received_vcs(&s);
      vi.set_missing_pps(&s);
    }

    // Multicast status to all replicas.
    s.authenticate();
    send(&s, All_replicas);
  }
}

bool Replica::shutdown()
{
  LOG_INFO << "Replica shutdown" << std::endl;
  START_CC(shutdown_time);
  vtimer->stop();

  // Rollback to last checkpoint
  if (!state.in_fetch_state())
  {
    Seqno rc = state.rollback(last_executed);
    last_tentative_execute = last_executed = rc;
  }

  if (id() == primary())
  {
    // Primary sends a view-change before shutting down to avoid
    // delaying client request processing for the view-change timeout
    // period.
    send_view_change();
  }

// TODO(#pbft): stub out, INSIDE_ENCLAVE
#ifndef INSIDE_ENCLAVE
  char ckpt_name[1024];
  sprintf(ckpt_name, "/tmp/%s_%d", service_name.c_str(), id());
  FILE* o = fopen(ckpt_name, "w");

  size_t sz = fwrite(&v, sizeof(View), 1, o);
  sz += fwrite(&limbo, sizeof(bool), 1, o);
  sz += fwrite(&has_nv_state, sizeof(bool), 1, o);

  sz += fwrite(&next_pp_seqno, sizeof(Seqno), 1, o);
  sz += fwrite(&last_stable, sizeof(Seqno), 1, o);
  sz += fwrite(&low_bound, sizeof(Seqno), 1, o);
  sz += fwrite(&last_prepared, sizeof(Seqno), 1, o);
  sz += fwrite(&last_executed, sizeof(Seqno), 1, o);
  sz += fwrite(&last_tentative_execute, sizeof(Seqno), 1, o);

  bool ret = true;
  for (Seqno i = last_stable + 1; i <= last_stable + max_out; i++)
  {
    ret &= plog.fetch(i).encode(o);
  }

  for (Seqno i = last_stable + 1; i <= last_stable + max_out; i++)
  {
    ret &= clog.fetch(i).encode(o);
  }

  for (Seqno i = last_stable; i <= last_stable + max_out; i++)
  {
    ret &= elog.fetch(i).encode(o);
  }

  ret &= state.shutdown(o, last_stable);
  ret &= vi.shutdown(o);

  fclose(o);
#endif
  STOP_CC(shutdown_time);

// TODO(#pbft): stub out, INSIDE_ENCLAVE
#ifndef INSIDE_ENCLAVE
  return ret & (sz == 9);
#else
  return true;
#endif
}

bool Replica::restart(FILE* in)
{
  LOG_INFO << "Replica restart" << std::endl;
  START_CC(restart_time);

// TODO(#pbft): stub out, INSIDE_ENCLAVE
#ifndef INSIDE_ENCLAVE
  bool ret = true;
  size_t sz = fread(&v, sizeof(View), 1, in);
  sz += fread(&limbo, sizeof(bool), 1, in);
  sz += fread(&has_nv_state, sizeof(bool), 1, in);

  limbo = (limbo != 0);
  cur_primary = v % num_replicas;
  if (v < 0 || id() == primary())
  {
    ret = false;
    v = 0;
    limbo = false;
    has_nv_state = true;
  }

  sz += fread(&next_pp_seqno, sizeof(Seqno), 1, in);
  sz += fread(&last_stable, sizeof(Seqno), 1, in);
  sz += fread(&low_bound, sizeof(Seqno), 1, in);
  sz += fread(&last_prepared, sizeof(Seqno), 1, in);
  sz += fread(&last_executed, sizeof(Seqno), 1, in);
  sz += fread(&last_tentative_execute, sizeof(Seqno), 1, in);

  ret &= (low_bound >= last_stable) & (last_tentative_execute >= last_executed);
  ret &= last_prepared >= last_tentative_execute;

  if (!ret)
  {
    low_bound = last_stable = last_tentative_execute = last_executed =
      last_prepared = 0;
  }

  plog.clear(last_stable + 1);
  for (Seqno i = last_stable + 1; ret && i <= last_stable + max_out; i++)
  {
    ret &= plog.fetch(i).decode(in);
  }

  clog.clear(last_stable + 1);
  for (Seqno i = last_stable + 1; ret && i <= last_stable + max_out; i++)
  {
    ret &= clog.fetch(i).decode(in);
  }

  elog.clear(last_stable);
  for (Seqno i = last_stable; ret && i <= last_stable + max_out; i++)
  {
    ret &= elog.fetch(i).decode(in);
  }

  ret &= state.restart(in, this, last_stable, last_tentative_execute, !ret);
  ret &= vi.restart(in, v, last_stable, !ret);
#endif

  STOP_CC(restart_time);

// TODO(#pbft): stub out, INSIDE_ENCLAVE
#ifndef INSIDE_ENCLAVE
  return ret & (sz == 9);
#else
  return true;
#endif
}

void Replica::recover()
{
  LOG_INFO << "Replica recovery" << std::endl;
// TODO(#pbft): stub out, INSIDE_ENCLAVE
#ifndef INSIDE_ENCLAVE
  corrupt = false;

  char ckpt_name[1024];
  sprintf(ckpt_name, "/tmp/%s_%d", service_name.c_str(), id());
  FILE* i = fopen(ckpt_name, "r");

  if (i == NULL || !restart(i))
  {
    // Replica is faulty; start from initial state.
    LOG_FAIL << "Unable to restart from checkpoint" << std::endl;
    corrupt = true;
  }

  // Initialize recovery variables:
  recovering = true;
  vc_recovering = false;
  se.clear();
  delete qs;
  qs = 0;
  rr_reps.clear();
  delete rr;
  rr = 0;
  recovery_point = Seqno_max;

  // Change my incoming session keys and zero client's keys.
  START_CC(nk_time);

  unsigned zk[Key_size_u];
  bzero(zk, Key_size);

  STOP_CC(nk_time);

  // Start estimation procedure.
  START_CC(est_time);
  qs = new Query_stable();
  send(qs, All_replicas);

  // Add my own reply-stable message to the estimator.
  Seqno lc = last_executed / checkpoint_interval * checkpoint_interval;
  std::shared_ptr<Principal> p = get_principal(id());
  Reply_stable* rs = new Reply_stable(lc, last_prepared, qs->nonce(), p.get());
  se.add(rs, true);
#endif
}

void Replica::handle(Query_stable* m)
{
  if (m->verify())
  {
    Seqno lc = last_executed / checkpoint_interval * checkpoint_interval;
    std::shared_ptr<Principal> p = get_principal(m->id());
    Reply_stable rs(lc, last_prepared, m->nonce(), p.get());

    // TODO: should put a bound on the rate at which I send these messages.
    send(&rs, m->id());
  }

  delete m;
}

void Replica::enforce_bound(Seqno b)
{
  PBFT_ASSERT(recovering && se.estimate() >= 0, "Invalid state");

  bool correct = !corrupt && last_stable <= b - max_out && next_pp_seqno <= b &&
    low_bound <= b && last_prepared <= b && last_tentative_execute <= b &&
    last_executed <= b &&
    (last_tentative_execute == last_executed ||
     last_tentative_execute == last_executed + 1);

  for (Seqno i = b + 1; correct && (i <= plog.max_seqno()); i++)
  {
    if (!plog.fetch(i).is_empty())
    {
      correct = false;
    }
  }

  for (Seqno i = b + 1; correct && (i <= clog.max_seqno()); i++)
  {
    if (!clog.fetch(i).is_empty())
    {
      correct = false;
    }
  }

  for (Seqno i = b + 1; correct && (i <= elog.max_seqno()); i++)
  {
    if (!elog.fetch(i).is_empty())
    {
      correct = false;
    }
  }

  Seqno known_stable = se.low_estimate();
  if (!correct)
  {
    LOG_FAIL << "Incorrect state setting low bound to " << known_stable
             << std::endl;
    next_pp_seqno = last_prepared = low_bound = last_stable = known_stable;
    last_tentative_execute = last_executed = 0;
    limbo = false;
    plog.clear(known_stable + 1);
    clog.clear(known_stable + 1);
    elog.clear(known_stable);
  }

  correct &= vi.enforce_bound(b, known_stable, !correct);
  correct &= state.enforce_bound(b, known_stable, !correct);
  corrupt = !correct;
}

void Replica::handle(Reply_stable* m)
{
  if (qs && qs->nonce() == m->nonce())
  {
    if (se.add(m))
    {
      // Done with estimation.
      delete qs;
      qs = 0;
      recovery_point = se.estimate() + max_out;

      enforce_bound(recovery_point);
      STOP_CC(est_time);

      LOG_INFO << "sending recovery request" << std::endl;
      // Send recovery request.
      START_CC(rr_time);
      rr = new Request(new_rid());

      int len;
      char* buf = rr->store_command(len);
      PBFT_ASSERT(len >= (int)sizeof(recovery_point), "Request is too small");
      memcpy(buf, &recovery_point, sizeof(recovery_point));

      rr->sign(sizeof(recovery_point));
      send(rr, primary());
      STOP_CC(rr_time);

      LOG_INFO << "Starting state checking" << std::endl;

      // Stop vtimer while fetching state. It is restarted when the fetch ends
      // in new_state.
      vtimer->stop();
      state.start_check(last_executed);

      rqueue.clear();
      ro_rqueue.clear();
    }
    return;
  }
  delete m;
}

void Replica::enforce_view(View rec_view)
{
  PBFT_ASSERT(recovering, "Invalid state");

  if (rec_view >= v || vc_recovering || (limbo && rec_view + 1 == v))
  {
    // Replica's view number is reasonable; do nothing.
    return;
  }

  corrupt = true;
  vi.clear();
  v = rec_view - 1;
  send_view_change();
}

void Replica::send_null()
{
  PBFT_ASSERT(id() == primary(), "Invalid state");

  Seqno max_rec_point = max_out +
    (max_rec_n + checkpoint_interval - 1) / checkpoint_interval *
      checkpoint_interval;

  if (max_rec_n && max_rec_point > last_stable && has_complete_new_view())
  {
    if (
      rqueue.size() == 0 && next_pp_seqno <= last_executed &&
      next_pp_seqno + 1 <= max_out + last_stable)
    {
      // Send null request if there is a recovery in progress and there
      // are no outstanding requests.
      next_pp_seqno++;
      LOG_INFO << " sending null pp for seqno " << next_pp_seqno << "\n";
      Req_queue empty;
      size_t requests_in_batch;

      Pre_prepare* pp =
        new Pre_prepare(view(), next_pp_seqno, empty, requests_in_batch);
      pp->set_digest();
      send(pp, All_replicas);
      plog.fetch(next_pp_seqno).add_mine(pp);
    }
  }
  ntimer->restart();

  // TODO: backups should force view change if primary does not send null
  // requests to allow recoveries to complete.
}

bool Replica::delay_vc()
{
  // delay the view change if checking or fetching state, if there are no longer
  // any requests in the request queue, or the request we were waiting for is no
  // longer in the queue
  return state.in_check_state() || state.in_fetch_state() ||
    (has_complete_new_view() &&
     (rqueue.size() == 0 || rqueue.first()->client_id() != cid_vtimer ||
      rqueue.first()->request_id() != rid_vtimer));
}

void Replica::start_vtimer_if_request_waiting()
{
  if (rqueue.size() > 0 && f() > 0)
  {
    Request* first = rqueue.first();
    cid_vtimer = first->client_id();
    rid_vtimer = first->request_id();
    vtimer->start();
  }
}

//
// Timeout handlers:
//

void Replica::vtimer_handler(void* owner)
{
  PBFT_ASSERT(replica, "replica is not initialized\n");

  if (!replica->delay_vc() && replica->f() > 0)
  {
    if (replica->rqueue.size() > 0)
    {
      LOG_INFO << "View change timer expired first rid: "
               << replica->rqueue.first()->request_id()
               << ", digest:" << replica->rqueue.first()->digest().hash()
               << " first cid: " << replica->rqueue.first()->client_id()
               << std::endl;
    }

    replica->send_view_change();
  }
  else
  {
    replica->vtimer->restart();
  }
}

void Replica::stimer_handler(void* owner)
{
  auto principals = ((Replica*)owner)->get_principals();
  if (principals->size() > 1)
  {
    ((Replica*)owner)->send_status();
  }
  ((Replica*)owner)->stimer->restart();
}

void Replica::btimer_handler(void* owner)
{
  PBFT_ASSERT(replica, "replica is not initialized\n");
  replica->btimer->restop();
  if (replica->primary() == replica->node_id)
  {
    ++stats.count_pre_prepare_batch_timer;
    replica->send_pre_prepare(true);
  }
}

void Replica::rec_timer_handler(void* owner)
{
  PBFT_ASSERT(replica, "replica is not initialized\n");
  static int rec_count = 0;

  replica->rtimer->restart();

  if (!replica->rec_ready)
  {
    // Replica is not ready to recover
    return;
  }

#ifdef RECOVERY
  if (
    replica->num_of_replicas() - 1 - rec_count % replica->num_of_replicas() ==
    replica->id())
  {
    // Start recovery:
    INIT_REC_STATS();

    if (replica->recovering)
    {
      INCR_OP(incomplete_recs);
      LOG_INFO << "* Starting recovery" << std::endl;
    }

    // Checkpoint
    replica->shutdown();

    replica->state.simulate_reboot();

    replica->recover();
  }
  else
  {
    if (replica->recovering)
    {
      INCR_OP(rec_overlaps);
    }
  }

#endif

  rec_count++;
}

void Replica::ntimer_handler(void* owner)
{
  ((Replica*)owner)->send_null();
}

void Replica::debug_slow_timer_handler(void* owner)
{
  ((Replica*)owner)->dump_state(std::cout);
  LOG_FATAL << "Execution took too long" << std::endl;
}

void Replica::dump_state(std::ostream& os)
{
  os << "Replica state: " << std::endl;
  os << "node_id: " << node_id << " view: " << v
     << " cur_primary:" << cur_primary << " next_pp_seqno: " << next_pp_seqno
     << " last_stable: " << last_stable << " low_bound: " << low_bound
     << std::endl;
  os << "last_prepared: " << last_prepared
     << " last_executed: " << last_executed
     << " last_tentative_execute: " << last_tentative_execute << std::endl;

  os << "============== rqueue: " << std::endl;
  rqueue.dump_state(os);

  os << "============== ro_rqueue: " << std::endl;
  ro_rqueue.dump_state(os);

  os << "============== plog: " << std::endl;
  plog.dump_state(os);

  os << "============== clog: " << std::endl;
  clog.dump_state(os);

  os << "============== elog: " << std::endl;
  elog.dump_state(os);

  os << "============== brt: " << std::endl;
  brt.dump_state(os);

  os << "============== stable_checkpoints: " << std::endl;
  for (auto& entry : stable_checkpoints)
  {
    os << " pid:" << entry.first << " seqno: " << entry.second->seqno()
       << " digest hash:" << entry.second->digest().hash() << std::endl;
  }

  os << "============== replies: " << std::endl;
  replies.dump_state(os);

  os << "============== state: " << std::endl;
  state.dump_state(os);

  os << "stimer state:" << stimer->get_state() << std::endl;

  os << "============== vtimer state:" << vtimer->get_state()
     << " limbo:" << limbo << " has_nv_message: " << vi.has_nv_message(v)
     << " has_complete_new_view: " << vi.has_complete_new_view(v)
     << " has_nv_state:" << has_nv_state << std::endl;

  os << "============== view info:" << std::endl;
  vi.dump_state(os);
}

void Replica::try_end_recovery()
{
  if (
    recovering && last_stable >= recovery_point && !state.in_check_state() &&
    rr_reps.is_complete())
  {
    // Done with recovery.
    END_REC_STATS();

    recovering = false;

    // Execute any buffered read-only requests
    for (Request* m = ro_rqueue.remove(); m != 0; m = ro_rqueue.remove())
    {
      execute_read_only(m);
      delete m;
    }
  }
}

int Replica::min_pre_prepare_batch_size =
  Replica::min_min_pre_prepare_batch_size;
