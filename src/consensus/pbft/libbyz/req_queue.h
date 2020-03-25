// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "ds/dl_list.h"
#include "ds/thread_messaging.h"
#include "pbft_assert.h"
#include "request.h"
#include "types.h"

#include <algorithm>
#include <unordered_map>

class Req_queue
{
  //
  // Implements a bounded queue of requests.
  //
public:
  Req_queue();
  // Effects: Creates an empty queue that can hold one request per principal.

  bool append(Request* r);
  // Effects: If there is space in the queue and there is no request
  // from "r->client_id()" with timestamp greater than or equal to
  // "r"'s in the queue then it: appends "r" to the queue, removes any
  // other request from "r->client_id()" from the queue and returns
  // true. Otherwise, returns false.

  bool is_in_rqueue(Request* r);
  // Effects: returns true if the request is in the rqueue

  Request* remove();
  // Effects: If there is any element in the queue, removes the first
  // element in the queue and returns it. Otherwise, returns 0.

  bool remove(int cid, Request_id rid);
  // Effects: If there are any requests from client "cid" with
  // timestamp less than or equal to "rid" removes those requests from
  // the queue. Otherwise, does nothing. In either case, it returns
  // true iff the first request in the queue is removed.

  Request* first() const;
  // Effects: If there is any element in the queue, returns a pointer to
  // the first request in the queue. Otherwise, returns 0.

  int size() const;
  // Effects: Returns the current size (number of elements) in queue.

  int num_bytes() const;
  // Effects: Return the number of bytes used by elements in the queue.

  void clear();
  // Effects: Removes all the requests from this.

  void dump_state(std::ostream& os);
  // Effects: Dumps state for debugging

private:
  struct RNode
  {
    std::unique_ptr<Request> r;
    RNode* next;
    RNode* prev;
  };

  // reqs has an entry for each principal indexed by principal id.
  struct Key
  {
    size_t cid;
    Request_id rid;
    bool operator==(const Key& o) const
    {
      return cid == o.cid && rid == o.rid;
    }
  };

  struct KeyHash
  {
    size_t operator()(const Key& k) const
    {
      return k.cid ^ k.rid;
    }
  };
  std::unordered_map<Key, std::unique_ptr<RNode>, KeyHash> reqs;
  mutable snmalloc::DLList<RNode>
    rnodes[enclave::ThreadMessaging::max_num_threads];
  mutable uint64_t count = 0;

  int nelems; // Number of elements in queue
  int nbytes; // Number of bytes in queue
};

inline int Req_queue::size() const
{
  return nelems;
}

inline int Req_queue::num_bytes() const
{
  return nbytes;
}

inline Request* Req_queue::first() const
{
  uint32_t tcount = enclave::ThreadMessaging::thread_count;
  tcount = std::max(tcount, (uint32_t)1);

  for (uint32_t i = 0; i < tcount; ++i)
  {
    count++;
    auto rn = rnodes[count % tcount].get_head();
    if (rn != nullptr)
    {
      PBFT_ASSERT(rn->r != 0, "Invalid state");
      return rn->r.get();
    }
  }
  return 0;
}