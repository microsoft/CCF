// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "digest.h"
#include "reply.h"
#include "time_types.h"
#include "types.h"

#include <sys/time.h>
#include <vector>

class Req_queue;

class Rep_info_exactly_once
{
  //
  // Holds the last replies sent to each principal.
  //
public:
  Rep_info_exactly_once(char* mem, int sz, int nps);
  // Requires: "mem" points to an array of "size" bytes and is virtual
  // memory page aligned.
  // Effects: Creates a new object that stores data in "mem" for "nps"
  // principals.

  ~Rep_info_exactly_once();

  Seqno total_requests_processed() const;
  // Returns the number of individual requests processed by the replica

  int size() const;
  // Effects: Returns the actual number of bytes (a multiple of the
  // virtual memory page size) that was consumed by this from the
  // start of the "mem" argument supplied to the constructor.

  Request_id req_id(int pid);
  // Requires: "pid" is a valid principal identifier.
  // Effects: Returns the timestamp in the last message sent to
  // principal "pid".

  Reply* reply(int pid);
  // Requires: "pid" is a valid principal identifier.
  // Effects: Returns a pointer to the last reply value sent to "pid"
  // or 0 if no such reply was sent.

  bool new_state(Req_queue* rset);
  // Effects: Updates this to reflect the new state and removes stale
  // requests from rset. If it removes the first request in "rset",
  // returns true; otherwise returns false.

  char* new_reply(int pid);
  // Requires: "pid" is a valid principal identifier.
  // Effects: Returns a pointer to a buffer where the new reply value
  // for principal "pid" can be placed. Sets the reply to tentative.

  int new_reply_size() const;
  // Returns the size of the reply buffer size

  void end_reply(int pid, Request_id rid, int size);
  // Requires: "pid" is a valid principal identifier.
  // Effects: Completes the construction of a new reply value: this is
  // informed that the reply value is size bytes long and computes its
  // digest.

  void commit_reply(int pid);
  // Requires: "pid" is a valid principal identifier.
  // Effects: Mark "pid"'s last reply committed.

  bool is_committed(int pid);
  // Requires: "pid" is a valid principal identifier.
  // Effects: Returns true iff the last reply sent to "pid" is
  // committed.

  void send_reply(int pid, View v, int id, bool tentative = true);
  // Requires: "pid" is a valid principal identifier and end_reply was
  // called after the last call to new_reply for "pid"
  // Effects: Sends a reply message to "pid" for view "v" from replica
  // "id" with the latest reply value stored in the buffer returned by
  // new_reply. If tentative is omitted or true, it sends the reply as
  // tentative unless it was previously committed

  void dump_state(std::ostream& os);
  // Effects: logs state for debugging

private:
  int nps;
  char* mem;
  std::vector<Reply*> reps; // vector of replies indexed by principal id.
  Seqno*
    total_processed; // total requests processed since replica started running
  static constexpr int Max_rep_size = 8192;

  struct Rinfo
  {
    bool tentative; // True if last reply is tentative and was not committed.
    Time lsent; // Time at which reply was last sent.
  };
  std::vector<Rinfo> ireps;
};

inline Seqno Rep_info_exactly_once::total_requests_processed() const
{
  return *total_processed;
}

inline int Rep_info_exactly_once::size() const
{
  return (nps + 1) * Max_rep_size + sizeof(Seqno);
}

inline void Rep_info_exactly_once::commit_reply(int pid)
{
  ireps[pid].tentative = false;
  ireps[pid].lsent = zero_time();
}

inline bool Rep_info_exactly_once::is_committed(int pid)
{
  return !ireps[pid].tentative;
}

inline Request_id Rep_info_exactly_once::req_id(int pid)
{
  return reps[pid]->request_id();
}

inline Reply* Rep_info_exactly_once::reply(int pid)
{
  return reps[pid];
}
