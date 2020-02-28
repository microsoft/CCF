// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Req_queue.h"

#include "Node.h"
#include "Pre_prepare.h"
#include "Request.h"

Req_queue::Req_queue() :
  reqs(Max_num_replicas),
  head(nullptr),
  tail(nullptr),
  nelems(0),
  nbytes(0)
{}

bool Req_queue::append(Request* r)
{
  size_t cid = r->client_id();
  Request_id rid = r->request_id();

  auto it = reqs.find({cid, rid});
  if (it == reqs.end())
  {
    nbytes += r->size();
    nelems++;
    auto rn = std::make_unique<RNode>();
    rn->r.reset(r);

    if (head == nullptr)
    {
      head = tail = rn.get();
      rn->prev = rn->next = nullptr;
    }
    else
    {
      tail->next = rn.get();
      rn->prev = tail;
      rn->next = nullptr;
      tail = rn.get();
    }

    reqs.insert({Key{cid, rid}, std::move(rn)});
    return true;
  }

  // this request is already in the queue
  return false;
}

bool Req_queue::is_in_rqueue(Request* r)
{
  size_t cid = r->client_id();
  Request_id rid = r->request_id();

  auto it = reqs.find({cid, rid});
  if (it == reqs.end())
  {
    return false;
  }
  return true;
}

Request* Req_queue::remove()
{
  if (head == nullptr)
  {
    return nullptr;
  }

  Request* ret = head->r.release();
  PBFT_ASSERT(ret != 0, "Invalid state");

  head = head->next;
  if (head != nullptr)
  {
    head->prev = nullptr;
  }
  else
  {
    tail = nullptr;
  }

  nelems--;
  nbytes -= ret->size();

  auto it = reqs.find({(size_t)ret->client_id(), ret->request_id()});
  reqs.erase(it);

  return ret;
}

bool Req_queue::remove(int cid, Request_id rid)
{
  auto it = reqs.find({(size_t)cid, rid});
  if (it == reqs.end())
  {
    return false;
  }

  std::unique_ptr<RNode> rn = std::move(it->second);
  nelems--;
  nbytes -= rn->r->size();

  bool ret = false;
  if (rn->prev == nullptr)
  {
    PBFT_ASSERT(head == rn.get(), "Invalid state");
    head = rn->next;
    ret = true;
  }
  else
  {
    rn->prev->next = rn->next;
  }

  if (rn->next == nullptr)
  {
    PBFT_ASSERT(tail == rn.get(), "Invalid state");
    tail = rn->prev;
  }
  else
  {
    rn->next->prev = rn->prev;
  }

  reqs.erase(it);

  return ret;
}

void Req_queue::clear()
{
  reqs.clear();
  head = tail = nullptr;
  nelems = nbytes = 0;
}

void Req_queue::dump_state(std::ostream& os)
{
  os << " nelems:" << nelems << std::endl;
  os << " Requests:" << std::endl;
  for (auto& p : reqs)
  {
    auto rnode = p.second.get();
    os << " cid: " << p.first.cid << " rid: " << p.first.rid
       << " prev: " << rnode->prev;
  }
}
