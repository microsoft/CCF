// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "big_req_table.h"

#include "ds/logger.h"
#include "pre_prepare.h"
#include "replica.h"
#include "request.h"

Big_req_table::Big_req_table(size_t num_of_replicas) :
  breqs(max_out),
  last_stable(0),
  last_view(0),
  unmatched(num_of_replicas)
{
  max_entries = max_out * Max_requests_in_batch;
}

Big_req_table::Big_req_table() :
  breqs(max_out),
  last_stable(0),
  last_view(0),
  unmatched(pbft::GlobalState::get_node().num_of_replicas())
{
  max_entries = max_out * Max_requests_in_batch;
}

Big_req_table::~Big_req_table()
{
  for (auto const& p : breqs)
  {
    delete p.second;
  }
}

inline void Big_req_table::remove_unmatched(BR_entry* bre)
{
  if (bre->maxn < 0)
  {
    PBFT_ASSERT(bre->r != 0, "Invalid state");
    auto& centry = unmatched[bre->r->client_id()];

    centry.list.remove(bre);
    centry.num_requests--;
    PBFT_ASSERT(centry.num_requests >= 0, "Should be positive");
  }
}

bool Big_req_table::add_pre_prepare(Digest& rd, int i, Seqno n, View v)
{
  BR_entry* bre;
  auto it = breqs.find(rd);
  if (it != breqs.end())
  {
    bre = it->second;

    remove_unmatched(bre);

    if (n > bre->maxn)
    {
      bre->maxn = n;
    }

    if (v > bre->maxv)
    {
      bre->maxv = v;
    }

    if (bre->r)
    {
      return true;
    }

    Waiting_pp wp;
    wp.i = i;
    wp.n = n;
    wp.v = v;
    bre->waiting.push_back(wp);
  }
  else
  {
    // No entry in breqs for rd
    bre = new BR_entry;
    bre->rd = rd;
    Waiting_pp wp;
    wp.i = i;
    wp.n = n;
    wp.v = v;
    bre->waiting.push_back(wp);
    bre->maxn = n;
    bre->maxv = v;
    breqs.insert({rd, bre});
  }

  return false;
}

void Big_req_table::refresh_entry(Digest& rd, int i, Seqno n, View v)
{
  auto it = breqs.find(rd);
  PBFT_ASSERT(it != breqs.end(), "Invalid state");
  BR_entry* bre = it->second;
  PBFT_ASSERT(bre != nullptr, "Invalid state");

  if (n > bre->maxn)
  {
    bre->maxn = n;
  }

  if (v > bre->maxv)
  {
    bre->maxv = v;
  }

  PBFT_ASSERT(bre->r != nullptr, "Invalid state");
}

void Big_req_table::add_pre_prepare(Request* r, Seqno n, View v)
{
  Digest rd = r->digest();
  auto it = breqs.find(rd);
  if (it != breqs.end())
  {
    auto bre = it->second;
    remove_unmatched(bre);

    if (n > bre->maxn)
    {
      bre->maxn = n;
    }

    if (v > bre->maxv)
    {
      bre->maxv = v;
    }

    if (bre->r == 0)
    {
      bre->r = r;
    }
    else
    {
      delete r;
    }
  }
  else
  {
    // No entry in breqs for rd
    auto bre = new BR_entry;
    bre->rd = rd;
    bre->r = r;
    bre->maxn = n;
    bre->maxv = v;
    breqs.insert({rd, bre});
  }
}

bool Big_req_table::check_pcerts(BR_entry* bre)
{
  PBFT_ASSERT(
    pbft::GlobalState::get_replica().has_complete_new_view(), "Invalid state");

  for (int i = 0; i < bre->waiting.size(); i++)
  {
    Waiting_pp wp = bre->waiting[i];
    if (
      pbft::GlobalState::get_replica().plog.within_range(wp.n) &&
      wp.v >= last_view)
    {
      Prepared_cert& pc = pbft::GlobalState::get_replica().plog.fetch(wp.n);
      if (pc.is_pp_correct())
      {
        return true;
      }
    }
  }
  return false;
}

bool Big_req_table::add_unmatched(BR_entry* e, Request*& old_req)
{
  auto& centry = unmatched[e->r->client_id()];
  old_req = 0;

  if (centry.num_requests >= Max_unmatched_requests_per_client)
  {
    LOG_FAIL_FMT(
      "Too many Requests pending from client: {}", e->r->client_id());
    old_req = centry.list.pop_tail()->r;
  }
  else
  {
    centry.num_requests++;
  }

  centry.list.insert(e);
  return true;
}

bool Big_req_table::add_request(Request* r, bool verified)
{
  PBFT_ASSERT(
    r->size() > Request::big_req_thresh && !r->is_read_only(),
    "Invalid Argument");

  Digest rd = r->digest();
  auto it = breqs.find(rd);
  if (it != breqs.end())
  {
    auto bre = it->second;

    if (
      bre->r == 0 &&
      (verified || !pbft::GlobalState::get_replica().has_complete_new_view() ||
       check_pcerts(bre)))
    {
      bre->r = r;

      std::vector<Waiting_pp> waiting = bre->waiting;
      bre->waiting.clear();

      while (waiting.size())
      {
        const Waiting_pp& wp = waiting.back();
        Seqno n = wp.n;
        int i = wp.i;
        View v = wp.v;
        waiting.pop_back();

        if (pbft::GlobalState::get_replica().has_complete_new_view())
        {
          // Missing pre-prepare is in replica's plog.
          if (
            v >= last_view &&
            pbft::GlobalState::get_replica().plog.within_range(n))
          {
            PBFT_ASSERT(n > last_stable, "Invalid state");
            Prepared_cert& pc = pbft::GlobalState::get_replica().plog.fetch(n);
            pc.add(bre->rd, i);
            pbft::GlobalState::get_replica().send_prepare(n);
          }
        }
        else
        {
          // Missing pre-prepare is in replica's view-info
          pbft::GlobalState::get_replica().vi.add_missing(bre->rd, n, i);
        }
      }

      return true;
    }
  }
  else if (verified)
  {
    // Buffer up to Max_unmatched_requests_per_client requests with the
    // largest timestamps from client.
    Request* old_req = 0;
    auto bre = new BR_entry();
    bre->rd = rd;
    bre->r = r;
    bool added = add_unmatched(bre, old_req);
    if (added)
    {
      breqs.insert({rd, bre});

      if (old_req)
      {
        auto it = breqs.find(old_req->digest());
        PBFT_ASSERT(it != breqs.end(), "Invalid state");
        auto old_entry = it->second;
        breqs.erase(it);
        delete old_entry;
      }

      return true;
    }
    else
    {
      bre->r = nullptr;
      delete bre;
    }
  }
  return false;
}

Request* Big_req_table::lookup(Digest& rd)
{
  auto it = breqs.find(rd);
  if (it != breqs.end())
  {
    return it->second->r;
  }
  return 0;
}

void Big_req_table::clear()
{
  for (auto it = breqs.begin(); it != breqs.end();)
  {
    auto bre = it->second;

    remove_unmatched(bre);
    delete bre;
    it = breqs.erase(it);
  }
}

void Big_req_table::mark_stable(Seqno ls, Req_queue& rqueue)
{
  last_stable = ls;

  for (auto it = breqs.begin(); it != breqs.end();)
  {
    auto bre = it->second;
    if (bre->maxn <= ls && bre->maxv >= 0)
    {
      if (bre->maxn < 0)
      {
        PBFT_ASSERT(bre->r != 0, "Invalid state");
        if (rqueue.is_in_rqueue(bre->r))
        {
          LOG_TRACE_FMT(
            "Request is in rqueue don't remove it from big req table {} {} {}",
            bre->r->request_id(),
            bre->r->client_id(),
            bre->r->digest().hash());
          it++;
          continue;
        }
      }
      remove_unmatched(bre);
      delete bre;
      it = breqs.erase(it);
    }
    else
    {
      it++;
    }
  }
}

void Big_req_table::view_change(View v)
{
  last_view = v;

  for (auto it = breqs.begin(); it != breqs.end();)
  {
    auto bre = it->second;

    if (bre->maxv < v)
    {
      remove_unmatched(bre);
      delete bre;
      it = breqs.erase(it);
    }
    else
    {
      it++;
    }
  }
}

void Big_req_table::dump_state(std::ostream& os)
{
  for (auto& entry : breqs)
  {
    os << " digest hash:" << entry.first.hash()
       << " r: " << (void*)entry.second->r << " maxn:" << entry.second->maxn
       << " maxv:" << entry.second->maxv;
    if (entry.second->r)
    {
      os << " cid:" << entry.second->r->client_id()
         << " rid:" << entry.second->r->request_id();
    }
    os << std::endl;
    os << " waiting:" << std::endl;
    for (auto& wentry : entry.second->waiting)
    {
      os << " n:" << wentry.n << " v:" << wentry.v << " i:" << wentry.i
         << std::endl;
    }
  }
}
