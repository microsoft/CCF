// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "replica.h"

#include "append_entries.h"
#include "checkpoint.h"
#include "commit.h"
#include "data.h"
#include "ds/logger.h"
#include "ds/serialized.h"
#include "ds/thread_messaging.h"
#include "fetch.h"
#include "itimer.h"
#include "k_max.h"
#include "ledger.h"
#include "message_tags.h"
#include "meta_data.h"
#include "meta_data_d.h"
#include "network.h"
#include "new_view.h"
#include "pbft_assert.h"
#include "pre_prepare.h"
#include "prepare.h"
#include "prepared_cert.h"
#include "principal.h"
#include "query_stable.h"
#include "reply.h"
#include "reply_stable.h"
#include "request.h"
#include "statistics.h"
#include "status.h"
#include "view_change.h"
#include "view_change_ack.h"

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
  pbft::RequestsMap& pbft_requests_map_,
  pbft::PrePreparesMap& pbft_pre_prepares_map_,
  ccf::Signatures& signatures,
  pbft::PbftStore& store) :
  Node(node_info),
  rqueue(),
  plog(max_out),
  clog(max_out),
  elog(max_out * 2, 0),
  stable_checkpoints(node_info.general_info.num_replicas),
  brt(node_info.general_info.num_replicas),
  pbft_requests_map(pbft_requests_map_),
  pbft_pre_prepares_map(pbft_pre_prepares_map_),
#ifdef ENFORCE_EXACTLY_ONCE
  replies(mem, nbytes, num_principals),
#else
  replies(mem, nbytes),
#endif
  rep_cb(nullptr),
  global_commit_cb(nullptr),
  entropy(tls::create_entropy()),
  state(
    this,
    mem,
    nbytes,
    node_info.general_info.num_replicas,
    node_info.general_info.max_faulty),
  se(node_info.general_info.num_replicas),
  rr_reps(
    node_info.general_info.max_faulty,
    node_info.general_info.max_faulty == 0 ?
      1 :
      node_info.general_info.num_replicas - node_info.general_info.max_faulty),
  vi(
    node_id,
    0,
    64, // make this dynamic - https://github.com/microsoft/CCF/issues/385
    node_info.general_info.num_replicas)
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

  vtimer =
    std::make_unique<ITimer>(vt + (uint64_t)id() % 100, vtimer_handler, this);
  stimer =
    std::make_unique<ITimer>(st + (uint64_t)id() % 100, stimer_handler, this);
  btimer = std::make_unique<ITimer>(
    max_pre_prepare_request_batch_wait_ms, btimer_handler, this);

  cid_vtimer = 0;
  rid_vtimer = 0;

#ifdef DEBUG_SLOW
  debug_slow_timer =
    std::make_unique<ITimer>(10 * 60 * 1000, debug_slow_timer_handler, this);
  debug_slow_timer->start();
#endif

#ifdef PROACTIVE_RECOVERY
  // Skew recoveries. It is important for nodes to recover in the reverse order
  // of their node ids to avoid a view-change every recovery which would degrade
  // performance.
  rtimer = std::make_unique<ITimer>(rt, rec_timer_handler, this);
  rec_ready = false;
  rtimer->start();
#endif

  ntimer = std::make_unique<ITimer>(30000 / max_out, ntimer_handler, this);

  recovering = false;
  qs = 0;
  rr = 0;
  recovery_point = Seqno_max;
  max_rec_n = 0;

  exec_command = nullptr;

  ledger_writer =
    std::make_unique<LedgerWriter>(store, pbft_pre_prepares_map, signatures);
  encryptor = store.get_encryptor();
}

void Replica::register_exec(ExecCommand e)
{
  exec_command = e;
}

Replica::~Replica() = default;

struct PreVerifyCbMsg
{
  Message* m;
  Replica* self;
};

struct PreVerifyResultCbMsg
{
  Message* m;
  Replica* self;
  bool result;
};

static void pre_verify_reply_cb(
  std::unique_ptr<enclave::Tmsg<PreVerifyResultCbMsg>> req)
{
  Message* m = req->data.m;
  Replica* self = req->data.self;
  bool result = req->data.result;

  if (result)
  {
    self->process_message(m);
  }
  else
  {
    LOG_INFO_FMT("did not verify - m:{}", m->tag());
    delete m;
  }
}

static void pre_verify_cb(std::unique_ptr<enclave::Tmsg<PreVerifyCbMsg>> req)
{
  Message* m = req->data.m;
  Replica* self = req->data.self;

  auto resp =
    std::make_unique<enclave::Tmsg<PreVerifyResultCbMsg>>(&pre_verify_reply_cb);

  resp->data.m = m;
  resp->data.self = self;
  resp->data.result = self->pre_verify(m);

  enclave::ThreadMessaging::thread_messaging.add_task<PreVerifyResultCbMsg>(
    enclave::ThreadMessaging::main_thread, std::move(resp));
}

static uint64_t verification_thread = 0;

Message* Replica::create_message(const uint8_t* data, uint32_t size)
{
  uint64_t alloc_size = size;

  Message* m;

  switch (Message::get_tag(data))
  {
    case Request_tag:
      m = new Request(alloc_size);
      break;

    case Reply_tag:
      m = new Reply(alloc_size);
      break;

    case Pre_prepare_tag:
      m = new Pre_prepare(alloc_size);
      break;

    case Prepare_tag:
      m = new Prepare(alloc_size);
      break;

    case Commit_tag:
      m = new Commit(alloc_size);
      break;

    case Checkpoint_tag:
      m = new Checkpoint(alloc_size);
      break;

#ifndef USE_PKEY_VIEW_CHANGES
    case View_change_ack_tag:
      m = new View_change_ack(alloc_size);
      break;
#endif

    case Status_tag:
      m = new Status(alloc_size);
      break;

    case Fetch_tag:
      m = new Fetch(alloc_size);
      break;

    case Query_stable_tag:
      m = new Query_stable(alloc_size);
      break;

    case Reply_stable_tag:
      m = new Reply_stable(alloc_size);
      break;

    case Meta_data_tag:
      m = new Meta_data(alloc_size);
      break;

    case Meta_data_d_tag:
      m = new Meta_data_d(alloc_size);
      break;

    case Data_tag:
      m = new Data(alloc_size);
      break;

    case View_change_tag:
      m = new View_change(alloc_size);
      break;

    case New_view_tag:
      m = new New_view((uint32_t)alloc_size);
      break;

    case New_principal_tag:
      m = new New_principal(alloc_size);
      break;

    case Network_open_tag:
      m = new Network_open((uint32_t)alloc_size);
      break;

    case Append_entries_tag:
      m = new Append_entries((uint32_t)alloc_size);
      break;

    default:
      // Unknown message type.
      auto err = fmt::format("Unknown message type:{}", Message::get_tag(data));
      LOG_FAIL_FMT(err);
      throw std::logic_error(err);
      return nullptr;
  }

  memcpy(m->contents(), data, size);

  return m;
}

void Replica::receive_message(const uint8_t* data, uint32_t size)
{
  Message* m = create_message(data, size);
  if (m == nullptr)
  {
    return;
  }

  uint32_t target_thread = 0;

  if (enclave::ThreadMessaging::thread_count > 1 && m->tag() == Request_tag)
  {
    uint32_t num_worker_thread = enclave::ThreadMessaging::thread_count - 1;
    target_thread = (((Request*)m)->user_id() % num_worker_thread) + 1;
  }

  if (f() != 0 && target_thread != 0)
  {
    auto msg = std::make_unique<enclave::Tmsg<PreVerifyCbMsg>>(&pre_verify_cb);

    msg->data.m = m;
    msg->data.self = this;

    enclave::ThreadMessaging::thread_messaging.add_task<PreVerifyCbMsg>(
      target_thread, std::move(msg));
  }
  else
  {
    if (pre_verify(m))
    {
      process_message(m);
    }
    else
    {
      LOG_INFO_FMT("did not verify - m:{}", m->tag());
      delete m;
    }
  }
}

bool Replica::compare_execution_results(
  const ByzInfo& info, Pre_prepare* pre_prepare)
{
  // We are currently not ordering the execution on the backups correctly.
  // This will be resolved in the immediate future.
  if (enclave::ThreadMessaging::thread_count > 2)
  {
    return true;
  }

  auto& r_pp_root = pre_prepare->get_replicated_state_merkle_root();

  auto execution_match = true;

  if (!std::equal(
        std::begin(r_pp_root),
        std::end(r_pp_root),
        std::begin(info.replicated_state_merkle_root)))
  {
    LOG_FAIL << "Replicated state merkle root between execution and the "
                "pre_prepare message does not match, seqno:"
             << pre_prepare->seqno() << std::endl;
    execution_match = false;
  }

  auto tx_ctx = pre_prepare->get_ctx();
  if (tx_ctx != info.ctx && info.ctx != std::numeric_limits<int64_t>::min())
  {
    LOG_FAIL << "User ctx between execution and the pre_prepare message "
                "does not match, seqno:"
             << pre_prepare->seqno() << ", tx_ctx:" << tx_ctx
             << ", info.ctx:" << info.ctx << std::endl;
    execution_match = false;
  }

  if (pre_prepare->did_exec_gov_req() != info.did_exec_gov_req)
  {
    LOG_FAIL_FMT(
      "If we executed a governance request between execution and the "
      "pre_prepare message does not match, seqno:{}, "
      "{} != {}",
      pre_prepare->seqno(),
      (pre_prepare->did_exec_gov_req() ? "true" : "false"),
      (info.did_exec_gov_req ? "true" : "false"));
    execution_match = false;
  }

  if (pre_prepare->last_exec_gov_req() != info.last_exec_gov_req)
  {
    LOG_FAIL_FMT(
      "If we executed a governance request between execution and the "
      "pre_prepare message does not match, seqno:{}, "
      "pp=>{} != {}<=info",
      pre_prepare->seqno(),
      pre_prepare->last_exec_gov_req(),
      info.last_exec_gov_req);
    execution_match = false;
  }

  if (!execution_match)
  {
    if (rollback_cb != nullptr)
    {
      rollback_cb(last_te_version, rollback_info);
    }
    last_tentative_execute--;
    return false;
  }

  last_te_version = info.ctx;

  return true;
}

void Replica::playback_request(ccf::Store::Tx& tx)
{
  auto view = tx.get_view(pbft_requests_map);
  auto req_v = view->get(0);
  PBFT_ASSERT(
    req_v.has_value(),
    "Deserialised request but it was not found in the requests map");
  auto request = req_v.value();

  LOG_TRACE_FMT(
    "Playback request for request with size {}", request.pbft_raw.size());
  auto req =
    create_message<Request>(request.pbft_raw.data(), request.pbft_raw.size());

  if (!waiting_for_playback_pp)
  {
    // only increment last tentative execute once per pre-prepare (a pre-prepare
    // could have batched requests but we can't increment last_tentative_execute
    // for each one individually)
    last_tentative_execute = last_tentative_execute + 1;
    LOG_TRACE_FMT(
      "in playback execute tentative with lte {}, le {}, for rid {} with cid "
      "{}",
      last_tentative_execute,
      last_executed,
      req->request_id(),
      req->client_id());
    // keep f before this request batch executes
    // to check on playback pre prepare if we should open the network
    playback_before_f = f();
  }

  waiting_for_playback_pp = true;

  vec_exec_cmds[0] = std::move(execute_tentative_request(
    *req, playback_max_local_commit_value, true, &tx, true));

  exec_command(vec_exec_cmds, playback_byz_info, 1, 0);
  did_exec_gov_req = did_exec_gov_req || playback_byz_info.did_exec_gov_req;

  auto owned_req = req.release();
  if (!brt.add_request(owned_req))
  {
    delete owned_req;
  }
}

void Replica::populate_certificates(Pre_prepare* pp, bool add_mine)
{
  if (pp->seqno() <= 0)
  {
    // first pre prepare will not contain proofs for a previous pre prepare
    return;
  }

  auto prev_seqno = pp->seqno() - 1;
  if (!plog.within_range(prev_seqno))
  {
    LOG_DEBUG_FMT(
      "seqno {} is out of range, can not add prepare proofs to plog",
      prev_seqno);
    return;
  }
  auto& prev_prepared_cert = plog.fetch(prev_seqno);
  auto prev_pp = prev_prepared_cert.pre_prepare();
  if (prev_pp != nullptr)
  {
    Pre_prepare::ValidProofs_iter vp_iter(prev_pp);
    int p_id;
    bool valid;
    while (vp_iter.get(p_id, valid) && valid)
    {
      LOG_DEBUG_FMT(
        "Adding prepare for principal with id {} for seqno {}",
        p_id,
        prev_seqno);
      Prepare* p = new Prepare(
        prev_pp->view(),
        prev_pp->seqno(),
        prev_pp->digest(),
        prev_pp->get_nonce(),
        nullptr,
        prev_pp->is_signed(),
        p_id);
      prev_prepared_cert.add(p);
    }
    if (add_mine)
    {
      LOG_DEBUG_FMT("Adding my prepare for seqno {}", prev_seqno);
      Prepare* p = new Prepare(
        prev_pp->view(),
        prev_pp->seqno(),
        prev_pp->digest(),
        prev_pp->get_nonce(),
        nullptr,
        prev_pp->is_signed());
      prev_prepared_cert.add_mine(p);
    }
  }
}

void Replica::playback_pre_prepare(ccf::Store::Tx& tx)
{
  auto view = tx.get_view(pbft_pre_prepares_map);
  auto pp = view->get(0);
  PBFT_ASSERT(
    pp.has_value(),
    "Deserialised pre prepare but it was not found in the pre prepares map");
  auto pre_prepare = pp.value();

  LOG_TRACE_FMT("playback pre-prepare {}", pre_prepare.seqno);
  auto executable_pp = create_message<Pre_prepare>(
    pre_prepare.contents.data(), pre_prepare.contents.size());
  auto seqno = executable_pp->seqno();
  playback_pp_seqno = seqno;
  waiting_for_playback_pp = false;
  playback_max_local_commit_value = INT64_MIN;

  playback_byz_info.last_exec_gov_req = gov_req_track.last_seqno();
  if (did_exec_gov_req)
  {
    gov_req_track.update(executable_pp->seqno());
    did_exec_gov_req = false;
  }

  if (compare_execution_results(playback_byz_info, executable_pp.get()))
  {
    next_pp_seqno = seqno;

    if (seqno > last_prepared)
    {
      last_prepared = seqno;
    }

    LOG_TRACE_FMT("Storing pre prepare at seqno {}", seqno);

    last_te_version = ledger_writer->write_pre_prepare(tx, executable_pp.get());

    global_commit(executable_pp.get());

    last_executed++;

    PBFT_ASSERT(
      last_executed <= executable_pp->seqno(),
      "last_executed and pre prepares seqno don't match in playback pre "
      "prepare");

    populate_certificates(executable_pp.get(), true);

    auto& prepared_cert = plog.fetch(executable_pp->seqno());
    prepared_cert.add(executable_pp.release());

    if (f() > 0 && (last_executed % checkpoint_interval == 0))
    {
      Seqno stable_point = std::max(
        last_executed - checkpoint_interval / 2, seqno_at_last_f_change);
      mark_stable(stable_point, true);
    }

    if (playback_before_f == 0 && f() != 0)
    {
      Network_open no(Node::id());
      send(&no, primary());
    }

    rqueue.clear();
  }
  else
  {
    throw std::logic_error(fmt::format(
      "Merkle roots don't match in playback pre-prepare for seqno {}",
      executable_pp->seqno()));
  }
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

  if (state.in_check_state())
  {
    state.check_state();
  }
}

void Replica::process_message(Message* m)
{
  PBFT_ASSERT(m->tag() != New_key_tag, "Tag no longer supported");

  if (is_exec_pending)
  {
    pending_recv_msgs.push_back(m);
    return;
  }

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
  auto n = reinterpret_cast<T*>(m);
  return n->pre_verify();
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

void Replica::handle(Request* m)
{
  bool ro = m->is_read_only();

  Digest rd = m->digest();
  LOG_TRACE << "Received request with rid: " << m->request_id()
            << " replier: " << m->replier() << " is_signed: " << m->is_signed()
            << " is read only: " << m->is_read_only()
            << " contents size: " << m->contents_size() << " id:" << id()
            << " primary:" << primary() << " with cid: " << m->client_id()
            << " current seqno: " << next_pp_seqno
            << " last executed: " << last_executed << " digest: " << rd.hash()
            << std::endl;

  if (has_complete_new_view())
  {
    LOG_TRACE << "Received request with rid: " << m->request_id()
              << " with cid: " << m->client_id() << std::endl;

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
  LOG_TRACE_FMT(
    "rqueue size {}, next_pp_seqno {}, last_executed {}, last_stable {}, has "
    "complete new view {}",
    rqueue.size(),
    next_pp_seqno,
    last_executed,
    last_stable,
    has_complete_new_view());
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
    auto ctx = std::make_unique<ExecTentativeCbCtx>();
    ctx->nonce = entropy->random64();

    Prepared_cert* ps = nullptr;
    if (next_pp_seqno > congestion_window)
    {
      ps = &plog.fetch(next_pp_seqno - congestion_window);
    }
    Pre_prepare* pp = new Pre_prepare(
      view(), next_pp_seqno, rqueue, ctx->requests_in_batch, ctx->nonce, ps);

    auto fn = [](
                Pre_prepare* pp,
                Replica* self,
                std::unique_ptr<ExecTentativeCbCtx> ctx) {
      ByzInfo& info = ctx->info;

      pp->set_last_gov_request(
        self->gov_req_track.last_seqno(), info.did_exec_gov_req);
      pp->set_merkle_roots_and_ctx(info.replicated_state_merkle_root, info.ctx);
      pp->set_digest(self->signed_version.load());
      self->plog.fetch(self->next_pp_seqno).add_mine(pp);

      info.last_exec_gov_req = self->gov_req_track.last_seqno();
      if (info.did_exec_gov_req)
      {
        self->gov_req_track.update(pp->seqno());
      }

      self->requests_per_batch.insert(
        {self->next_pp_seqno, ctx->requests_in_batch});

      if (self->ledger_writer)
      {
        self->last_te_version = self->ledger_writer->write_pre_prepare(pp);
      }
      if (pbft::GlobalState::get_node().f() > 0)
      {
        self->send(pp, All_replicas);
      }
      else
      {
        self->send_prepare(self->next_pp_seqno, info);
      }
      self->try_send_prepare();
    };

    is_exec_pending = true;
    if (execute_tentative(pp, fn, std::move(ctx)))
    {
      LOG_DEBUG << "adding to plog from pre prepare: " << next_pp_seqno
                << std::endl;
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
      try_send_prepare();
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
  if (playback_pp_seqno >= m->seqno() || waiting_for_playback_pp)
  {
    LOG_TRACE_FMT("Reject pre prepare with seqno {}", m->seqno());
    delete m;
    return;
  }

  const Seqno ms = m->seqno();

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
      if (ms == playback_pp_seqno + 1)
      {
        // previous pre prepare was executed during playback, we need to add the
        // prepares for it, as the prepare proofs for the previous pre-prepare
        // are in the next pre prepare message
        populate_certificates(m);
      }
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

void Replica::try_send_prepare()
{
  is_exec_pending = false;
  while (!pending_recv_msgs.empty() && !is_exec_pending)
  {
    Message* m = pending_recv_msgs.front();
    pending_recv_msgs.pop_front();
    process_message(m);
  }
}

void Replica::send_prepare(Seqno seqno, std::optional<ByzInfo> byz_info)
{
  if (plog.within_range(seqno))
  {
    is_exec_pending = true;
    Prepared_cert& pc = plog.fetch(seqno);

    if (pc.my_prepare() == 0 && pc.is_pp_complete())
    {
      bool send_only_to_self = (f() == 0);
      // Send prepare to all replicas and log it.
      Pre_prepare* pp = pc.pre_prepare();

      auto fn = [](
                  Pre_prepare* pp,
                  Replica* self,
                  std::unique_ptr<ExecTentativeCbCtx> msg) {
        if (self->ledger_writer && !self->is_primary())
        {
          msg->info.last_exec_gov_req = self->gov_req_track.last_seqno();
          if (!self->compare_execution_results(msg->info, pp))
          {
            PBFT_ASSERT_FMT_FAIL(
              "Merkle roots don't match in send prepare for seqno {}",
              msg->seqno);

            self->try_send_prepare();
            return;
          }

          if (msg->info.did_exec_gov_req)
          {
            self->gov_req_track.update(pp->seqno());
          }

          if (self->ledger_writer)
          {
            self->last_te_version = self->ledger_writer->write_pre_prepare(pp);
          }
        }

        Prepare* p = new Prepare(
          self->v,
          pp->seqno(),
          pp->digest(),
          msg->nonce,
          nullptr,
          pp->is_signed());
        int send_node_id =
          (msg->send_only_to_self ? self->node_id : All_replicas);
        self->send(p, send_node_id);
        Prepared_cert& pc = self->plog.fetch(msg->seqno);
        pc.add_mine(p);
        LOG_DEBUG << "added to pc in prepare: " << pp->seqno() << std::endl;

        if (pc.is_complete())
        {
          LOG_TRACE << "pc is complete for seqno: " << msg->seqno
                    << " and sending commit" << std::endl;
          self->send_commit(msg->seqno, send_node_id == self->node_id);
        }

        self->is_exec_pending = false;
        self->send_prepare(msg->seqno + 1, msg->orig_byzinfo);
      };

      auto msg = std::make_unique<ExecTentativeCbCtx>();
      msg->seqno = seqno;
      msg->send_only_to_self = send_only_to_self;
      msg->orig_byzinfo = byz_info;
      msg->nonce = entropy->random64();
      if (byz_info.has_value())
      {
        msg->info = byz_info.value();
        fn(pp, this, std::move(msg));
      }
      else
      {
        if (!execute_tentative(pp, fn, std::move(msg)))
        {
          try_send_prepare();
        }
      }
      return;
    }
  }
  try_send_prepare();
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
  if (playback_pp_seqno >= m->seqno() || waiting_for_playback_pp)
  {
    LOG_TRACE_FMT("Reject prepare with seqno {}", m->seqno());
    delete m;
    return;
  }

  const Seqno ms = m->seqno();
  // Only accept prepare messages that are not sent by the primary for
  // current view.
  if (
    in_wv(m) && ms > low_bound && primary() != m->id() &&
    has_complete_new_view())
  {
    Prepared_cert& ps = plog.fetch(ms);
    if (ps.add(m) && ps.is_complete())
    {
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
  if (playback_pp_seqno >= m->seqno() || waiting_for_playback_pp)
  {
    LOG_TRACE_FMT("Reject commit with seqno {}", m->seqno());
    delete m;
    return;
  }
  const Seqno ms = m->seqno();

  // Only accept messages with the current view.
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

  if (ms > last_executed || ms > last_tentative_execute)
  {
    LOG_TRACE_FMT(
      "Received Checkpoint out of order from {} with seqno {}", m->id(), ms);
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
  rollback_to_globally_comitted();

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

void Replica::register_global_commit(
  global_commit_handler_cb cb, pbft::GlobalCommitInfo* gb_info)
{
  global_commit_cb = cb;
  global_commit_info = gb_info;
}

void Replica::register_mark_stable(
  mark_stable_handler_cb cb, pbft::MarkStableInfo* ms_info)
{
  mark_stable_cb = cb;
  mark_stable_info = ms_info;
}

void Replica::register_rollback_cb(
  rollback_handler_cb cb, pbft::RollbackInfo* rb_info)
{
  rollback_cb = cb;
  rollback_info = rb_info;
}

template <class T>
std::unique_ptr<T> Replica::create_message(
  const uint8_t* message_data, size_t data_size)
{
  auto msg_type = reinterpret_cast<T*>(create_message(message_data, data_size));
  return std::unique_ptr<T>(msg_type);
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

  seqno_at_last_f_change = last_executed + 1;
  mark_stable(last_executed, true);
  Node::set_f(f);
}

void Replica::emit_signature_on_next_pp(int64_t version)
{
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

char* Replica::create_response_message(
  int client_id, Request_id request_id, uint32_t size, uint64_t nonce)
{
  return replies.new_reply(
    client_id, request_id, last_tentative_execute, nonce, size);
}

void Replica::handle(Status* m)
{
  static const int max_ret_bytes = 65536;

  if (qs == 0)
  {
    Time current;
    Time t_sent = 0;
    current = ITimer::current_time();
    std::shared_ptr<Principal> p =
      pbft::GlobalState::get_node().get_principal(m->id());
    if (!p)
    {
      return;
    }

    // Retransmit messages that the sender is missing.

    if (last_stable > m->last_stable() + max_out)
    {
      LOG_TRACE_FMT("Sending append entries");
      // Node is so out-of-date that it will not accept any
      // pre-prepare/prepare/commmit messages in my log.
      // Send a stable checkpoint message for my stable checkpoint.

      Append_entries ae;
      send(&ae, m->id());

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

    LOG_TRACE_FMT(
      "my last stable {}, m->laststable {}, last executed {}, m->last_executed "
      "{}, max_out {}",
      last_stable,
      m->last_stable(),
      last_executed,
      m->last_executed(),
      max_out);

    if (m->view() < v)
    {
      // Retransmit my latest view-change message
      View_change* vc = vi.my_view_change(t_sent);
      if (vc != 0)
      {
        LOG_TRACE_FMT(
          "Re transmitting view change with digest: {}", vc->digest().hash());
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
        LOG_TRACE_FMT("Retransmitting from min {} to max {}", min, max);
        if (
          last_stable > m->last_stable() &&
          last_executed > m->last_executed() + 1)
        {
          LOG_TRACE_FMT(
            "Sending append entries to {} since we are way off", m->id());
          Append_entries ae;
          send(&ae, m->id());
        }
        else
        {
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
                  LOG_TRACE_FMT(
                    "Retransmitting request with id {} and cid {}",
                    r->request_id(),
                    r->client_id());
                  INCR_OP(message_counts_retransmitted[m->tag()]);
                  send(r, m->id());
                  count += r->size();
                }
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
          LOG_TRACE_FMT(
            "Re transmitting view change with digest: {}", vc->digest().hash());
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
  LOG_INFO_FMT(
    "Received view change for {} from {} with digest {}, v: {}",
    m->view(),
    m->id(),
    m->digest().hash(),
    v);

  if (m->id() == primary() && m->view() > v)
  {
    // "m" was sent by the primary for v and has a view number
    // higher than v: move to the next view.
    send_view_change();
  }
  vi.add(std::unique_ptr<View_change>(m));

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

  rollback_to_globally_comitted();

  last_prepared = last_executed;

  for (Seqno i = last_stable + 1; i <= last_stable + max_out; i++)
  {
    Prepared_cert& pc = plog.fetch(i);
    pc.update();
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

    LOG_TRACE_FMT(
      "Writing view for {} with digest {} to ledger",
      vc->view(),
      vc->digest().hash());

    ledger_writer->write_view_change(vc);
  }
}

void Replica::handle(New_principal* m)
{
  LOG_INFO << "received new message to add principal, id:" << m->id()
           << std::endl;

  std::vector<uint8_t> cert(m->cert().begin(), m->cert().end());
  PrincipalInfo info{
    m->id(), m->port(), m->ip(), cert, m->host_name(), m->is_replica()};

  pbft::GlobalState::get_node().add_principal(info);
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
    if (primary() == id())
    {
      send_pre_prepare();
    }
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

  pbft::GlobalState::get_replica().set_next_expected_sig_offset();

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
    View prev_view;
    auto pp = vi.fetch_request(i, d, prev_view);
    Prepared_cert& pc = plog.fetch(i);
    PBFT_ASSERT(pp != 0 && pp->digest() == d, "Invalid state");

    Pre_prepare::Requests_iter iter(pp);
    Request request;

    size_t req_in_pp = 0;

    while (iter.get(request))
    {
      req_in_pp++;
    }

    if (primary() == id())
    {
      ByzInfo info;
      pc.add_mine(pp);
      if (execute_tentative(pp, info, pp->get_nonce()))
      {
        if (ledger_writer && req_in_pp > 0)
        {
          last_te_version = ledger_writer->write_pre_prepare(pp, prev_view);
        }
      }
    }
    else
    {
      ByzInfo info;
      pc.add_old(pp);
      uint64_t nonce = entropy->random64();

      if (execute_tentative(pp, info, nonce))
      {
        if (ledger_writer && req_in_pp > 0)
        {
          last_te_version = ledger_writer->write_pre_prepare(pp, prev_view);
        }
      }

      Prepare* p = new Prepare(v, i, d, nonce, nullptr, pp->is_signed());
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
    send_status();
  }
  else
  {
    PBFT_ASSERT(last_executed >= last_stable, "Invalid state");
  }

  if (primary() != id() && rqueue.size() > 0)
  {
    start_vtimer_if_request_waiting();
  }
  if (encryptor)
  {
    encryptor->set_view(v);
  }
  LOG_INFO << "Done with process new view " << v << std::endl;
}

Pre_prepare* Replica::prepared_pre_prepare(Seqno n, bool was_f_0)
{
  Prepared_cert& pc = plog.fetch(n);
  if (pc.is_complete(was_f_0))
  {
    return pc.pre_prepare();
  }
  return 0;
}

Pre_prepare* Replica::committed(Seqno s, bool was_f_0)
{
  Pre_prepare* pp = prepared_pre_prepare(s, was_f_0);
  if (clog.fetch(s).is_complete() || was_f_0)
  {
    return pp;
  }
  return 0;
}

void Replica::rollback_to_globally_comitted()
{
  if (last_tentative_execute > last_gb_seqno)
  {
    // Rollback to last checkpoint
    PBFT_ASSERT(!state.in_fetch_state(), "Invalid state");

    auto rv = last_gb_version + 1;

    if (rollback_cb != nullptr)
    {
      rollback_cb(rv, rollback_info);
    }

    Seqno rc = state.rollback(last_gb_seqno);

    LOG_INFO_FMT(
      "Rolled back in view change to seqno {}, to version {}, last_executed "
      "was {}, last_tentative_execute was {}, "
      "last gb seqno {}, last gb version was {}",
      rc,
      rv,
      last_executed,
      last_tentative_execute,
      last_gb_seqno,
      last_gb_version);

    last_tentative_execute = rc;
    last_executed = rc;
    last_te_version = rv;
    LOG_INFO_FMT(
      "Roll back done, last tentative execute and last executed are {} {}",
      last_tentative_execute,
      last_executed);
    gov_req_track.rollback(rc);
  }
}

void Replica::global_commit(Pre_prepare* pp)
{
  if (pp->is_signed())
  {
    if (pp->seqno() >= last_gb_seqno && pp->get_ctx() >= last_gb_version)
    {
      LOG_TRACE_FMT("Global_commit: {} {}", pp->get_ctx(), pp->seqno());
      LOG_TRACE_FMT("Checkpointing for seqno {}", pp->seqno());
      state.checkpoint(pp->seqno());
      last_gb_version = pp->get_ctx();
      last_gb_seqno = pp->seqno();
      if (global_commit_cb != nullptr)
      {
        global_commit_cb(pp->get_ctx(), pp->view(), global_commit_info);
      }
    }
    signed_version = 0;
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
    if (f() == 0)
    {
      global_commit(pp);
    }
  }
}

std::unique_ptr<ExecCommandMsg> Replica::execute_tentative_request(
  Request& request,
  int64_t& max_local_commit_value,
  bool include_markle_roots,
  ccf::Store::Tx* tx,
  Seqno seqno)
{
  auto stash_replier = request.replier();
  request.set_replier(-1);
  int client_id = request.client_id();

  auto cmd = std::make_unique<ExecCommandMsg>(
    client_id,
    request.request_id(),
    reinterpret_cast<uint8_t*>(request.contents()),
    request.contents_size(),
    include_markle_roots,
    replies.total_requests_processed(),
    last_tentative_execute,
    max_local_commit_value,
    stash_replier,
    request.user_id(),
    &Replica::execute_tentative_request_end,
    tx);

  // Obtain "in" and "out" buffers to call exec_command
  cmd->inb.contents = request.command(cmd->inb.size);

  LOG_TRACE_FMT(
    "before exec command with seqno: {} rid {} cid {} rid digest {}",
    seqno,
    cmd->rid,
    request.client_id(),
    request.digest().hash());

  return cmd;
}

void Replica::execute_tentative_request_end(ExecCommandMsg& msg, ByzInfo& info)
{
  // Finish constructing the reply.
  right_pad_contents(msg.outb);
  Request r(reinterpret_cast<Request_rep*>(msg.req_start));
  r.set_replier(msg.replier);

  if (info.ctx > msg.max_local_commit_value)
  {
    msg.max_local_commit_value = info.ctx;
  }

  info.ctx = msg.max_local_commit_value;

  pbft::GlobalState::get_replica().replies.end_reply(
    msg.client, msg.rid, msg.last_tentative_execute, msg.outb.size);
}

bool Replica::create_execute_commands(
  Pre_prepare* pp,
  int64_t& max_local_commit_value,
  std::array<std::unique_ptr<ExecCommandMsg>, Max_requests_in_batch>& cmds,
  uint32_t& num_requests)
{
  if (
    pp->seqno() == last_tentative_execute + 1 && !state.in_fetch_state() &&
    !state.in_check_state() && has_complete_new_view())
  {
    last_tentative_execute = last_tentative_execute + 1;
    LOG_TRACE << "in execute tentative with last_tentative_execute: "
              << last_tentative_execute
              << " and last_executed: " << last_executed << std::endl;
    Pre_prepare::Requests_iter iter(pp);
    Request request;

    num_requests = 0;
    while (iter.get(request))
    {
      auto cmd = execute_tentative_request(
        request,
        max_local_commit_value,
        !iter.has_more_requests(),
        nullptr,
        pp->seqno());
      cmds[num_requests] = std::move(cmd);
      ++num_requests;
    }
    return true;
  }
  return false;
}

bool Replica::execute_tentative(Pre_prepare* pp, ByzInfo& info, uint64_t nonce)
{
  LOG_DEBUG_FMT(
    "in execute tentative for seqno {} and last_tentnative_execute {}",
    pp->seqno(),
    last_tentative_execute);

  uint32_t num_requests;
  if (create_execute_commands(
        pp, info.max_local_commit_value, vec_exec_cmds, num_requests))
  {
    exec_command(vec_exec_cmds, info, num_requests, nonce);
    return true;
  }
  return false;
}

void Replica::execute_tentative_callback(void* ctx)
{
  auto msg = std::unique_ptr<ExecuteTentativeCbMsg>(
    reinterpret_cast<ExecuteTentativeCbMsg*>(ctx));
  msg->fn(msg->pp, msg->self, std::move(msg->ctx));
}

bool Replica::execute_tentative(
  Pre_prepare* pp,
  void(cb)(Pre_prepare*, Replica*, std::unique_ptr<ExecTentativeCbCtx>),
  std::unique_ptr<ExecTentativeCbCtx> ctx)
{
  uint32_t num_requests;
  if (create_execute_commands(
        pp, ctx->info.max_local_commit_value, vec_exec_cmds, num_requests))
  {
    uint64_t nonce = ctx->nonce;
    ByzInfo& info = ctx->info;
    if (cb != nullptr)
    {
      if (node_info.general_info.support_threading)
      {
        auto msg = new ExecuteTentativeCbMsg();
        msg->self = this;
        msg->pp = pp;
        msg->fn = cb;
        msg->ctx = std::move(ctx);
        msg->ctx->info.cb = &execute_tentative_callback;
        msg->ctx->info.cb_ctx = msg;
      }
      else
      {
        ctx->info.cb = nullptr;
        ctx->info.cb_ctx = nullptr;
      }
    }

    exec_command(vec_exec_cmds, info, num_requests, nonce);
    if (!node_info.general_info.support_threading)
    {
      cb(pp, this, std::move(ctx));
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
          auto executed_ok = execute_tentative(pp, info, pp->get_nonce());
          PBFT_ASSERT(
            executed_ok,
            "tentative execution while executing committed failed");

          info.last_exec_gov_req = gov_req_track.last_seqno();
          if (!compare_execution_results(info, pp))
          {
            LOG_INFO_FMT(
              "Merkle roots don't match in execute committed for seqno {}",
              pp->seqno());
            return;
          }
          last_te_version = ledger_writer->write_pre_prepare(pp);
          PBFT_ASSERT(
            last_executed + 1 == last_tentative_execute,
            "last tentative did not advance with last executed");
          LOG_DEBUG << "Executed tentative in committed for: " << pp->seqno()
                    << " execution result true or false: " << executed_ok
                    << std::endl;
        }

        set_min_pre_prepare_batch_size();

        execute_prepared(true);
        global_commit(pp);
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
            LOG_TRACE_FMT(
              "Removed request with cid rid {} {}",
              client_id,
              request.request_id());
            vtimer->stop();
          }
        }

        // Send and log Checkpoint message for the new state if needed
        if (f() > 0 && (last_executed % checkpoint_interval == 0))
        {
          Digest d_state;
          Seqno stable_point = std::max(
            last_executed - checkpoint_interval / 2, seqno_at_last_f_change);
          state.digest(stable_point, d_state);
          Checkpoint* e = new Checkpoint(stable_point, d_state);
          Certificate<Checkpoint>& cc = elog.fetch(stable_point);
          cc.add_mine(e);

          send(e, All_replicas);

          if (cc.is_complete())
          {
            mark_stable(stable_point, true);
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
  brt.mark_stable(last_stable, rqueue);
  gov_req_track.mark_stable(last_stable - 1);

  if (mark_stable_cb != nullptr)
  {
    mark_stable_cb(mark_stable_info);
  }

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

void Replica::handle(Query_stable* m)
{
  if (m->verify())
  {
    Seqno lc = last_executed / checkpoint_interval * checkpoint_interval;
    std::shared_ptr<Principal> p = get_principal(m->id());
    Reply_stable rs(lc, last_prepared, m->nonce(), p.get());

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
      rr = new Request(new_rid(), -1, sizeof(recovery_point));

      int len;
      char* buf = rr->store_command(len);
      PBFT_ASSERT(len >= (int)sizeof(recovery_point), "Request is too small");
      memcpy(buf, &recovery_point, sizeof(recovery_point));

      rr->sign(sizeof(recovery_point));
      send(rr, primary());

      LOG_INFO << "Starting state checking" << std::endl;

      // Stop vtimer while fetching state. It is restarted when the fetch ends
      // in new_state.
      vtimer->stop();
      state.start_check(last_executed);

      rqueue.clear();
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

      Prepared_cert* ps = nullptr;
      if (next_pp_seqno != 0)
      {
        ps = &plog.fetch(next_pp_seqno - 1);
      }

      uint64_t nonce = entropy->random64();
      Pre_prepare* pp = new Pre_prepare(
        view(), next_pp_seqno, empty, requests_in_batch, nonce, ps);
      pp->set_digest();
      send(pp, All_replicas);
      plog.fetch(next_pp_seqno).add_mine(pp);
    }
  }
  ntimer->restart();
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
  if (
    !pbft::GlobalState::get_replica().delay_vc() &&
    pbft::GlobalState::get_replica().f() > 0)
  {
    if (pbft::GlobalState::get_replica().rqueue.size() > 0)
    {
      LOG_INFO
        << "View change timer expired first rid: "
        << pbft::GlobalState::get_replica().rqueue.first()->request_id()
        << ", digest:"
        << pbft::GlobalState::get_replica().rqueue.first()->digest().hash()
        << " first cid: "
        << pbft::GlobalState::get_replica().rqueue.first()->client_id()
        << std::endl;
    }

    pbft::GlobalState::get_replica().send_view_change();
  }
  else
  {
    pbft::GlobalState::get_replica().vtimer->restart();
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
  pbft::GlobalState::get_replica().btimer->restop();
  if (
    pbft::GlobalState::get_replica().primary() ==
    pbft::GlobalState::get_replica().node_id)
  {
    ++stats.count_pre_prepare_batch_timer;
    pbft::GlobalState::get_replica().send_pre_prepare(true);
  }
}

void Replica::rec_timer_handler(void* owner)
{
  static int rec_count = 0;

  pbft::GlobalState::get_replica().rtimer->restart();

  if (!pbft::GlobalState::get_replica().rec_ready)
  {
    // Replica is not ready to recover
    return;
  }

#ifdef RECOVERY
  if (
    pbft::GlobalState::get_replica().num_of_replicas() - 1 -
      rec_count % pbft::GlobalState::get_replica().num_of_replicas() ==
    pbft::GlobalState::get_replica().id())
  {
    // Start recovery:
    INIT_REC_STATS();

    if (pbft::GlobalState::get_replica().recovering)
    {
      INCR_OP(incomplete_recs);
      LOG_INFO << "* Starting recovery" << std::endl;
    }

    // Checkpoint
    pbft::GlobalState::get_replica().shutdown();

    pbft::GlobalState::get_replica().state.simulate_reboot();

    pbft::GlobalState::get_replica().recover();
  }
  else
  {
    if (pbft::GlobalState::get_replica().recovering)
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
  }
}

int Replica::min_pre_prepare_batch_size =
  Replica::min_min_pre_prepare_batch_size;