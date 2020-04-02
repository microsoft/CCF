// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "rep_info_exactly_once.h"

#include "replica.h"
#include "reply.h"
#include "req_queue.h"
#include "statistics.h"

#include <stdlib.h>
#include <string.h>

Rep_info_exactly_once::Rep_info_exactly_once(char* m, int sz, int n)
{
  PBFT_ASSERT(n != 0, "Invalid argument");

  nps = n;
  mem = m;

  if (sz < size())
  {
    PBFT_FAIL("Memory is too small to hold replies for all principals");
  }

  int old_nps = *((Long*)mem);
  if (old_nps != 0)
  {
    // Memory has already been initialized.
    if (nps != old_nps)
    {
      PBFT_FAIL("Changing number of principals. Not implemented yet");
    }
  }
  else
  {
    // Initialize memory.
    bzero(mem, size());
    for (int i = 0; i < nps; i++)
    {
      // Wasting first page just to store the number of principals.
      Reply_rep* rr = (Reply_rep*)(mem + (i + 1) * Max_rep_size);
      rr->tag = Reply_tag;
      rr->reply_size = -1;
      rr->rid = 0;
    }
    *((Long*)mem) = nps;
    total_processed = (Seqno*)(mem + size() - sizeof(Seqno));
  }

  struct Rinfo ri;
  ri.tentative = true;
  ri.lsent = zero_time();

  for (int i = 0; i < nps; i++)
  {
    Reply_rep* rr = (Reply_rep*)(mem + (i + 1) * Max_rep_size);
    PBFT_ASSERT(rr->tag == Reply_tag, "Corrupt memory");
    reps.push_back(new Reply(rr));
    ireps.push_back(ri);
  }
}

Rep_info_exactly_once::~Rep_info_exactly_once()
{
  for (int i = 0; i < nps; i++)
  {
    delete reps[i];
  }
}

char* Rep_info_exactly_once::new_reply(int pid)
{
  Reply* r = reps[pid];

  ireps[pid].tentative = true;
  ireps[pid].lsent = zero_time();

  pbft::GlobalState::get_replica().modify(&r->rep(), sizeof(Reply_rep));
  r->rep().reply_size = -1;
  return r->contents() + sizeof(Reply_rep);
}

int Rep_info_exactly_once::new_reply_size() const
{
  return Max_rep_size - sizeof(Reply_rep) - MAC_size;
}

void Rep_info_exactly_once::end_reply(int pid, Request_id rid, int sz)
{
  Reply* r = reps[pid];
  PBFT_ASSERT(r->rep().reply_size == -1, "Invalid state");

  Reply_rep& rr = r->rep();
  rr.rid = rid;
  rr.reply_size = sz;

  int old_size = sizeof(Reply_rep) + rr.reply_size;
  r->set_size(old_size + MAC_size);
  bzero(r->contents() + old_size, MAC_size);
}

void Rep_info_exactly_once::send_reply(int pid, View v, int id, bool tentative)
{
  Reply* r = reps[pid];
  Reply_rep& rr = r->rep();
  int old_size = sizeof(Reply_rep) + rr.reply_size;

  PBFT_ASSERT(rr.reply_size != -1, "Invalid state");
  PBFT_ASSERT(rr.extra == 0 && rr.v == 0 && rr.replica == 0, "Invalid state");

  if (!tentative && ireps[pid].tentative)
  {
    ireps[pid].tentative = false;
    ireps[pid].lsent = zero_time();
  }

  Time cur;
  Time& lsent = ireps[pid].lsent;
  if (lsent != 0)
  {
    cur = ITimer::current_time();
    if (diff_time(cur, lsent) <= ITimer::length_10_ms())
    {
      return;
    }

    lsent = cur;
  }

  if (ireps[pid].tentative)
  {
    rr.extra = 1;
  }
  rr.v = v;
  rr.replica = id;

  INCR_OP(reply_auth);

  r->auth_type = Auth_type::out;
  r->auth_len = sizeof(Reply_rep);
  r->auth_src_offset = 0;
  r->auth_dst_offset = old_size;

  pbft::GlobalState::get_node().send(r, pid);

  // Undo changes. To ensure state matches across all replicas.
  rr.extra = 0;
  rr.v = 0;
  rr.replica = 0;
  bzero(r->contents() + old_size, MAC_size);
}

bool Rep_info_exactly_once::new_state(Req_queue* rset)
{
  bool first = false;
  for (int i = 0; i < nps; i++)
  {
    commit_reply(i);

    // Remove requests from rset with stale timestamps.
    if (rset->remove(i, req_id(i)))
    {
      first = true;
    }
  }
  return first;
}

void Rep_info_exactly_once::dump_state(std::ostream& os)
{
  for (int i = 0; i < reps.size(); i++)
  {
    os << "i: " << i << " rid: " << reps[i]->request_id()
       << " tentative:" << ireps[i].tentative << std::endl;
  }
}
