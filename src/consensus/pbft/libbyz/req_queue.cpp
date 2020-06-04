// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "req_queue.h"

#include "node.h"
#include "pre_prepare.h"
#include "request.h"

Req_queue::Req_queue() : nelems(0), nbytes(0) {}

bool Req_queue::append(Request* r)
{
  size_t cid = r->client_id();
  Request_id rid = r->request_id();
  int user_id = r->user_id();
  auto it = reqs[user_id].find({cid, rid});
  if (it == reqs[user_id].end())
  {
    nbytes += r->size();
    nelems++;
    auto rn = std::make_unique<RNode>();
    rn->r.reset(r);

    rnodes[user_id].insert_back(rn.get());

    reqs[user_id].insert({Key{cid, rid}, std::move(rn)});
    return true;
  }

  // this request is already in the queue
  LOG_TRACE_FMT(
    "Did not insert request to req_queue, cid:{}, rid:{}", cid, rid);
  return false;
}

bool Req_queue::is_in_rqueue(Request* r)
{
  size_t cid = r->client_id();
  Request_id rid = r->request_id();
  int user_id = r->user_id();

  auto it = reqs[user_id].find({cid, rid});
  if (it == reqs[user_id].end())
  {
    return false;
  }
  return true;
}

Request* Req_queue::remove()
{
  uint32_t tcount = threading::ThreadMessaging::thread_count;
  tcount = std::max(tcount, (uint32_t)1);

  bool found = false;
  for (uint32_t i = 0; i < tcount; ++i)
  {
    if (!rnodes[count % tcount].is_empty())
    {
      found = true;
      break;
    }
    count++;
  }

  if (!found)
  {
    return nullptr;
  }

  auto rn = rnodes[count % tcount].pop();
  Request* ret = rn->r.release();
  CCF_ASSERT(ret != 0, "Invalid state");

  nelems--;
  nbytes -= ret->size();

  int user_id = ret->user_id();
  auto it = reqs[user_id].find({(size_t)ret->client_id(), ret->request_id()});
  reqs[user_id].erase(it);

  count++;
  return ret;
}

bool Req_queue::remove(int cid, Request_id rid, int user_id)
{
  auto it = reqs[user_id].find({(size_t)cid, rid});
  if (it == reqs[user_id].end())
  {
    return false;
  }

  std::unique_ptr<RNode> rn = std::move(it->second);
  nelems--;
  nbytes -= rn->r->size();

  rnodes[rn->r->user_id()].remove(rn.get());

  reqs[user_id].erase(it);

  return true;
}

void Req_queue::clear()
{
  uint32_t tcount = threading::ThreadMessaging::thread_count;
  // There is a corner case when we run the very first transaction that
  // thread_count can be 0. The use of std::max is a work around.
  tcount = std::max(tcount, (uint32_t)1);
  for (uint32_t i = 0; i < tcount; ++i)
  {
    while (!rnodes[i].is_empty())
    {
      rnodes[i].pop();
    }
  }
  for (auto& r : reqs)
  {
    r.clear();
  }
  nelems = nbytes = 0;
}

void Req_queue::dump_state(std::ostream& os)
{
  os << " nelems:" << nelems << std::endl;
  os << " Requests:" << std::endl;
  for (auto& req : reqs)
  {
    for (auto& p : req)
    {
      auto rnode = p.second.get();
      os << " cid: " << p.first.cid << " rid: " << p.first.rid
         << " prev: " << rnode->prev;
    }
  }
}
