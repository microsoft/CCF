// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "bitmap.h"
#include "digest.h"
#include "itimer.h"
#include "log.h"
#include "partition.h"
#include "pbft_assert.h"
#include "time_types.h"
#include "types.h"

#include <memory>
#include <unordered_map>
//
// Auxiliary classes:
//
struct Block;
struct Part;
class FPartQueue;
class CPartQueue;
class Data;
class Meta_data;
class Meta_data_d;
class Fetch;
class Replica;
class Meta_data_cert;
struct DSum;

// Key for partition map in checkpoint records
class PartKey
{
public:
  PartKey();
  PartKey(size_t l, size_t i);

  void operator=(PartKey const& x);
  size_t hash() const;
  bool operator==(PartKey const& x) const;

  size_t level : 8;
  size_t index : 56;
};

struct PartKeyHash
{
  size_t operator()(const PartKey& p) const
  {
    return p.hash();
  }
};

// Checkpoint record
class Checkpoint_rec
{
public:
  Checkpoint_rec();
  // Effects: Creates an empty checkpoint record.

  ~Checkpoint_rec();
  // Effects: Deletes record an all parts it contains

  void clear();
  // Effects: Deletes all parts in record and removes them.

  bool is_empty();
  // Effects: Returns true iff Checkpoint record is not in use.

  bool is_complete();
  // Effects: Returns false

  void append(int l, size_t i, Part* p);
  // Requires: fetch(l, i) == 0
  // Effects: Appends partition index "i" at level "l" with value "p"
  // to the record.

  void appendr(int l, size_t i, Part* p);
  // Effects: Like append but without the requires clause. If fetch(l,
  // i) != 0 it retains the old mapping.

  Part* fetch(int l, size_t i);
  // Effects: If there is a partition with index "i" from level "l" in
  // this, returns a pointer to its information. Otherwise, returns 0.

  int num_entries() const;
  // Effects: Returns the number of entries in the record.

  class Iter
  {
  public:
    Iter(Checkpoint_rec* r) : it(r->parts.begin()), end(r->parts.end()) {}
    // Effects: Return an iterator for the partitions in r.

    bool get(int& level, size_t& index, Part*& p);

  private:
    std::unordered_map<PartKey, Part*, PartKeyHash>::iterator it;
    std::unordered_map<PartKey, Part*, PartKeyHash>::iterator end;
  };
  friend class Iter;

  void print();
  // Effects: Prints description of this to stdout

  void dump_state(std::ostream& os);

  Digest sd; // state digest at the time the checkpoint is taken

private:
  // Map for partitions that were modified since this checkpoint was
  // taken and before the next checkpoint.
  std::unordered_map<PartKey, Part*, PartKeyHash> parts;
};

class State
{
public:
  State(
    Replica* replica,
    char* memory,
    size_t num_bytes,
    size_t num_of_replicas,
    size_t f);
  // Requires: mem is Block aligned and contains an integral number of
  // Blocks.
  // Effects: Creates an object that handles state digesting and
  // checkpointing for the region starting at "mem" with size
  // "num_bytes".

  ~State();
  // Effects: Deallocates all storage associated with state.

  void update();
  //
  // Maintaining checkpoints
  //
  void cow_single(int bindex);
  // Effects: Copies block with bindex and marks it as copied.

  void cow(char* mem, int size);
  // Effects: Performs copies for the blocks in the region
  // starting at "mem" and of size "size"
  // if they have not been copied since last checkpoint.
  // It also marks them as copied.

  void checkpoint(Seqno seqno);
  // Effects: Saves a checkpoint of the current state (associated with
  // seqno) and computes the digest of all partition.

  void discard_checkpoints(Seqno seqno, Seqno le);
  // Effects: Calls checkpoint(seqno) if seqno is greater than
  // the last checkpoint taken and le (the last executed sequence number)
  // is greater than or equal to seqno. Discards checkpoint records
  // with sequence number less than seqno.

  Seqno rollback(Seqno last_executed);
  // Requires: !in_fetch_state && there is a checkpoint in this
  // Effects: Rolls back to the last checkpoint with sequence number
  // less than or equal to last_executed and returns its sequence number.

  void compute_full_digest();
  // Effects: Computes a state digest from scratch and a digest for
  // each partition.

  bool digest(Seqno n, Digest& d);
  // Effects: If there is a checkpoint for sequence number "n" in
  // this, returns true and sets "d" to its digest. Otherwise, returns
  // false.

  //
  // Fetching missing state
  //
  bool in_fetch_state() const;
  // Effects: Returns true iff the replica is fetching missing state.

  void start_fetch(
    Seqno last_exec, Seqno c = -1, Digest* cd = 0, bool stable = false);
  // Effects: Sends fetch message for missing state. If "c != -1" then
  // "cd" points to the digest of checkpoint sequence number "c". "stable"
  // should be true iff the specific checkpoint being fetched is stable.

  void send_fetch(bool change_replier = false);
  // Effects: Sends fetch message requesting missing state. If
  // change_replier is true changes the selected replier.

  bool in_check_state() const;
  // Effects: Returns true iff the replica is checking state

  void start_check(Seqno last_exec);
  // Effects: Starts checking state that reflects execution up to "last_exec"

  void check_state();
  // Effects: checks if state is correct.

  bool enforce_bound(Seqno b, Seqno ks, bool corrupt);
  // Effects: Enforces that there is no information above bound
  // "b". "ks" is the maximum sequence number that I know is stable.

  // Message handlers
  void handle(Meta_data* m);
  void handle(Meta_data_d* m);
  void handle(Data* m);

  bool handle(Fetch* m, Seqno last_stable);
  // Effects: Returns true if it was able to verify the message and
  // false otherwise.

  void mark_stale();
  // Effects: Discards incomplete certificate.

  bool retrans_fetch(Time cur) const;
  // Effects: Returns true iff fetch should be retransmitted

  void dump_state(std::ostream& os);
  // Effects: Logs the state for debugging

private:
  // Parent replica object.
  Replica* replica;

  // Actual memory holding current state and the number of Blocks
  // in that memory.
  Block* mem;
  size_t nb;
  char* end_mem;

  // Bitmap with a bit for each block in the memory region indicating
  // whether the block should be copied the next time it is written;
  // blocks should be copied iff their bit is 0.
  Bitmap cowb;

  std::array<std::unique_ptr<Part[]>, PLevels> ptree; // Partition tree.
  std::array<std::unique_ptr<Digest[]>, PLevels>
    stree; // Tree of digests of subpartitions.

  Log<Checkpoint_rec> checkpoint_log; // Checkpoint log
  Seqno lc; // Sequence number of the last checkpoint

  //
  // Information used while fetching state.
  //
  bool fetching; // true iff replica is fetching missing state
  bool keep_ckpts; // whether to keep last checkpoints
  int flevel; // level of state partition info being fetched
  std::array<std::unique_ptr<FPartQueue>, PLevels>
    stalep; // queue of out-of-date partitions for each level

  std::unique_ptr<Meta_data_cert>
    cert; // certificate for partition we are working on
  int lreplier; // id of last replica we chose as replier
  Time last_fetch_t; // Time when last fetch was sent.

  //
  // Information used while checking state during recovery
  //
  bool checking; // true iff replica is checking state
  Seqno check_start; // last checkpoint sequence number when checking started
  bool corrupt; // true iff replica's state is known to be corrupt
  int poll_cnt; // check for messages after digesting this many blocks

  // queue of partitions whose digests need to be checked. It can have
  // partitions from different levels.
  std::unique_ptr<CPartQueue> to_check;
  int lchecked; // index of last block checked in to_check.high().
  int refetch_level; // level of ancestor of current partition whose
                     // subpartitions have already been added to to_check.

  int digest(Digest& d, int l, size_t i);
  // Effects: Sets "d" to the current digest of partition  "(l,i)"
  // Returns: size of object in partition (l,i)

  void digest(Digest& d, size_t i, Seqno lm, char* data, int size);
  // Effects: Sets "d" to Digest(i#lm#(data,size))

  bool check_digest(Digest& d, Meta_data* m);
  // Effects: Checks if the digest of the partion in "m" is "d"

  void done_with_level();
  // Requires: flevel has an empty out-of-date queue.
  // Effects: It decrements flevel and, if parent is consistent,
  // removes parent. If the queue of parent becomes empty it calls
  // itself recursively. Unless there is no parent, in which case it
  // in_fetch_state_to false and updates state accordingly.

  void update_ptree(Seqno n);
  // Effects: Updates the digests of the blocks whose cow bits were reset
  // since the last checkpoint and computes a new state digest using the
  // state digest computed during the last checkpoint.

  char* get_data(Seqno c, int i);
  // Requires: There is a checkpoint with sequence number "c" in this
  // Effects: Returns a pointer to the data for block index "i" at
  // checkpoint "c". [objsz gets the size of the object]

  Part& get_meta_data(Seqno c, int l, int i);
  // Requires: There is a checkpoint with sequence number "c" in this
  // Effects: Returns a pointer to the information for partition "(l,i)" at
  // checkpoint "c".

  bool check_data(int i);
  // Effects: Checks whether the actual digest of block "i" and its
  // digest in the ptree match.
};

inline bool State::in_fetch_state() const
{
  return fetching;
}

inline bool State::in_check_state() const
{
  return checking;
}

inline bool State::retrans_fetch(Time cur) const
{
  return fetching && diff_time(cur, last_fetch_t) > ITimer::length_100_ms();
}
