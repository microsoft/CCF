// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "digest.h"
#include "message.h"
#include "parameters.h"
#include "types.h"
class Principal;

//
// Meta_data_d messages contain the digests of a partition for all the
// checkpoints in the state of the sending replica. They have the
// following format:
//
#pragma pack(push)
#pragma pack(1)
struct Meta_data_d_rep : public Message_rep
{
  Request_id rid; // timestamp of fetch request
  Seqno ls; // sequence number of last checkpoint known to be stable at sender
  size_t l; // level of meta-data information in hierarchy
  size_t i; // index of partition within level

  // Digests for partition for each checkpoint held by the sender in
  // order of increasing sequence number. A null digest means the
  // sender does not have the corresponding checkpoint state.
  Digest digests[max_out / checkpoint_interval + 1];
  int n_digests; // number of digests in digests

  int id; // id of sender
  // Followed by a MAC.
};
#pragma pack(pop)

static_assert(
  sizeof(Meta_data_d_rep) + pbft_max_signature_size < Max_message_size,
  "Invalid size");

class Meta_data_d : public Message
{
  //
  //  Meta_data_d messages
  //
public:
  Meta_data_d(uint32_t msg_size = 0) : Message(msg_size) {}

  Meta_data_d(Request_id r, int l, size_t i, Seqno ls);
  // Effects: Creates a new un-authenticated Meta_data_d message with no
  // partition digests.

  void add_digest(Seqno n, Digest& digest);
  // Requires: "n%checkpoint_interval = 0", and "last_stable() <= n <=
  // last_stable()+max_out".
  // Effects: Adds the digest of the partition for sequence number "n" to this.

  void authenticate(Principal* p);
  // Effects: Computes a MAC for the message with the key shared with
  // "p" using the most recent keys.

  Request_id request_id() const;
  // Effects: Fetches the request identifier from the message.

  Seqno last_stable() const;
  // Effects: Fetches the sequence number of last stable checkpoint in message.

  Seqno last_checkpoint() const;
  // Effects: Fetches the sequence number of last stable checkpoint in message.

  int num_digests() const;
  // Effects: Returns the number of digests in the message.

  int level() const;
  // Effects: Returns the level of the partition

  size_t index() const;
  // Effects: Returns the index of the partition within its level

  int id() const;
  // Effects: Fetches the identifier of the replica from the message.

  bool digest(Seqno n, Digest& d);
  // Effects: If there is a digest for this partition at sequence
  // number "n" sets "d" to its value and returns true. Otherwise,
  // returns false.

  bool verify();
  // Effects: Verifies if the message is correct and authenticated by
  // replica rep().id.

private:
  Meta_data_d_rep& rep() const;
  // Effects: Casts "msg" to a Meta_data_d_rep&
};

inline Meta_data_d_rep& Meta_data_d::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Meta_data_d_rep*)msg);
}

inline Request_id Meta_data_d::request_id() const
{
  return rep().rid;
}

inline Seqno Meta_data_d::last_stable() const
{
  return rep().ls;
}

inline Seqno Meta_data_d::last_checkpoint() const
{
  return rep().ls + (rep().n_digests - 1) * checkpoint_interval;
}

inline int Meta_data_d::num_digests() const
{
  return rep().n_digests;
}

inline int Meta_data_d::level() const
{
  return rep().l;
}

inline size_t Meta_data_d::index() const
{
  return rep().i;
}

inline int Meta_data_d::id() const
{
  return rep().id;
}
