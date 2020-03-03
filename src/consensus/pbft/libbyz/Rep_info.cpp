// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Rep_info.h"

#include "Replica.h"
#include "Reply.h"
#include "Req_queue.h"
#include "Statistics.h"

#include <stdlib.h>
#include <string.h>

Rep_info::Rep_info(char* m, int sz) : reps(Max_num_replicas)
{
  mem = m;

  if (sz < size())
  {
    PBFT_FAIL("Memory is too small to hold replies");
  }

  // Initialize memory.
  bzero(mem, size());
  total_processed = (Seqno*)mem;
}

void Rep_info::count_request()
{
  pbft::GlobalState::get_replica().modify(mem, sizeof(Seqno));
  (*total_processed)++;
}

char* Rep_info::new_reply(
  int pid, Request_id rid, Seqno n, uint32_t message_size)
{
  message_size += sizeof(Reply_rep) + MAC_size;
  auto r = std::make_unique<Reply>(0, rid, n, 0, message_size);
  PBFT_ASSERT(r != nullptr, "Out of memory");
  r->set_size(message_size);
  r->trim();
  char* ret = r->contents() + sizeof(Reply_rep);
  std::lock_guard<SpinLock> mguard(lock);
  auto ret_insert = reps.insert({Key{(size_t)pid, rid, n}, std::move(r)});
  if (ret_insert.second)
  {
    return ret;
  }

  return nullptr;
}

int Rep_info::new_reply_size() const
{
  return Max_rep_size - sizeof(Reply_rep) - MAC_size;
}

void Rep_info::end_reply(int pid, Request_id rid, Seqno n, int size)
{
  std::lock_guard<SpinLock> mguard(lock);
  auto it = reps.find({(size_t)pid, rid, n});
  if (it != reps.end())
  {
    Reply* r = it->second.get();
    Reply_rep& rr = r->rep();
    rr.rid = rid;
    rr.reply_size = size;
    rr.digest = Digest(r->contents() + sizeof(Reply_rep), size);
    int old_size = sizeof(Reply_rep) + rr.reply_size;
    r->set_size(old_size + MAC_size);
    return;
  }

  LOG_INFO << " Attempt to end reply not in this < " << pid << "," << rid << ","
           << n << ">" << std::endl;
}

Reply* Rep_info::reply(int pid, Request_id rid, Seqno n)
{
  std::lock_guard<SpinLock> mguard(lock);
  auto it = reps.find({(size_t)pid, rid, n});
  if (it != reps.end())
  {
    return it->second.get();
  }

  return nullptr;
}

void Rep_info::send_reply(int pid, Request_id rid, Seqno n, View v, int id)
{
  std::lock_guard<SpinLock> mguard(lock);
  auto it = reps.find({(size_t)pid, rid, n});
  if (it != reps.end())
  {
    Reply* r = it->second.get();
    Reply_rep& rr = r->rep();

    PBFT_ASSERT(rr.reply_size != -1, "Invalid state");
    PBFT_ASSERT(rr.extra == 0 && rr.v == 0 && rr.replica == 0, "Invalid state");

    int old_size = sizeof(Reply_rep) + rr.reply_size;

    rr.extra = 1;
    rr.v = v;
    rr.replica = id;

    r->auth_type = Auth_type::out;
    r->auth_len = sizeof(Reply_rep);
    r->auth_src_offset = 0;
    r->auth_dst_offset = old_size;

    pbft::GlobalState::get_node().send(r, pid);
    reps.erase(it);
    return;
  }

  LOG_INFO << " Attempt to send reply not in this < " << pid << "," << rid
           << "," << n << ">" << std::endl;
}

void Rep_info::clear()
{
  std::lock_guard<SpinLock> mguard(lock);
  reps.clear();
}

void Rep_info::dump_state(std::ostream& os)
{
  std::lock_guard<SpinLock> mguard(lock);
  for (auto& pair : reps)
  {
    os << " cid: " << pair.first.cid << " rid: " << pair.first.rid
       << " seqno: " << pair.first.n
       << " digest hash:" << pair.second->digest().hash() << std::endl;
  }
}
