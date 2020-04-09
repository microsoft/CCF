// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "digest.h"
#include "message.h"
#include "partition.h"
#include "types.h"

//
// Meta_data messages contain information about a partition and its
// subpartitions. They have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Part_info
{
  size_t i; // index of sub-partition within its level
  Digest d; // digest of sub-partition
};

struct Meta_data_rep : public Message_rep
{
  Request_id rid; // timestamp of fetch request
  Seqno lu; // last seqno for which information in this is up-to-date
  Seqno lm; // seqno of last checkpoint that modified partition
  size_t l; // level of partition in hierarchy
  size_t i; // index of partition within level
  Digest d; // partition's digest
  int id; // id of sender
  int np; // number of sub-partitions included in message (i.e.,
          // sub-partitions modified by a checkpoint with seqno
          // greater than the lu on fetch)
  // Part_info parts[np]; // array of subpartition information
};
#pragma pack(pop)

static_assert(
  sizeof(Meta_data_rep) + sizeof(Part_info) * PChildren +
      pbft_max_signature_size <
    Max_message_size,
  "Invalid size");

class Meta_data : public Message
{
  //
  //  Meta_data messages
  //
public:
  Meta_data(uint32_t msg_size = 0) : Message(msg_size) {}

  Meta_data(Request_id r, int l, size_t i, Seqno lu, Seqno lm, Digest& d);
  // Effects: Creates a new un-authenticated Meta_data message with no
  // subpartition information.

  void add_sub_part(size_t index, Digest& digest);
  // Effects: Adds information about the subpartition "index" to this.

  Request_id request_id() const;
  // Effects: Fetches the request identifier from the message.

  Seqno last_uptodate() const;
  // Effects: Fetches the last seqno at which partition is up-to-date at sending
  // replica.

  Seqno last_mod() const;
  // Effects: Fetches seqno of last checkpoint that modified partition.

  int level() const;
  // Effects: Returns the level of the partition

  size_t index() const;
  // Effects: Returns the index of the partition within its level

  int id() const;
  // Effects: Fetches the identifier of the replica from the message.

  Digest& digest();
  // Effects: Returns the digest of the partition.

  int num_sparts() const;
  // Effects: Returns the number of subpartitions in this.

  class Sub_parts_iter
  {
    // An iterator for yielding all the sub_partitions of this partition
    // in order.
  public:
    Sub_parts_iter(Meta_data* m);
    // Requires: Meta_data is known to be valid
    // Effects: Return an iterator for the sub-partitions of the partition
    // in "m".

    bool get(size_t& index, Digest& d);
    // Effects: Modifies "d" to contain the digest of the next
    // subpartition and returns true. If there are no more
    // subpartitions, it returns false. It returns null digests for
    // subpartitions that were not modified since "f->seqno()", where
    // "f" is the fetch message that triggered this reply.

  private:
    Meta_data* msg;
    int cur_mod;
    int max_mod;
    size_t index;
    size_t max_index;
  };
  friend class Sub_parts_iter;

  bool verify();
  // Effects: Verifies if the message is correct

private:
  Meta_data_rep& rep() const;
  // Effects: Casts "msg" to a Meta_data_rep&

  Part_info* parts();
};

inline Meta_data_rep& Meta_data::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Meta_data_rep*)msg);
}

inline Part_info* Meta_data::parts()
{
  return (Part_info*)(contents() + sizeof(Meta_data_rep));
}

inline Request_id Meta_data::request_id() const
{
  return rep().rid;
}

inline Seqno Meta_data::last_uptodate() const
{
  return rep().lu;
}

inline Seqno Meta_data::last_mod() const
{
  return rep().lm;
}

inline int Meta_data::level() const
{
  return rep().l;
}

inline size_t Meta_data::index() const
{
  return rep().i;
}

inline int Meta_data::id() const
{
  return rep().id;
}

inline Digest& Meta_data::digest()
{
  return rep().d;
}

inline int Meta_data::num_sparts() const
{
  return rep().np;
}
