// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "digest.h"
#include "message.h"
#include "types.h"

class Principal;

//
// Fetch messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Fetch_rep : public Message_rep
{
  Request_id rid; // sequence number to prevent replays
  size_t level; // level of partition
  size_t index; // index of partition within level
  Seqno lu; // information for partition is up-to-date till seqno lu
  Seqno rc; // specific checkpoint requested (-1) if none
  int repid; // id of designated replier (valid if c >= 0)
  int id; // id of the replica that generated the message.

  // Followed by an authenticator.
};
#pragma pack(pop)

static_assert(
  sizeof(Fetch_rep) + pbft_max_signature_size < Max_message_size,
  "Invalid size");

class Fetch : public Message
{
  //
  // Fetch messages
  //
public:
  Fetch(uint32_t msg_size = 0) : Message(msg_size) {}

  Fetch(
    Request_id rid,
    Seqno lu,
    int level,
    size_t index,
    Seqno rc = -1,
    int repid = -1);
  // Effects: Creates a new authenticated Fetch message.

  void re_authenticate(Principal* p = 0);
  // Effects: Recomputes the authenticator in the message using the
  // most recent keys. If "p" is not null, may only update "p"'s
  // entry.

  Request_id request_id() const;
  // Effects: Fetches the request identifier from the message.

  Seqno last_uptodate() const;
  // Effects: Fetches the last up-to-date sequence number from the message.

  int level() const;
  // Effects: Returns the level of the partition

  size_t index() const;
  // Effects: Returns the index of the partition within its level

  int id() const;
  // Effects: Fetches the identifier of the replica from the message.

  Seqno checkpoint() const;
  // Effects: Returns the specific checkpoint requested or -1

  int replier() const;
  // Effects: If checkpoint() > 0, returns the designated replier. Otherwise,
  // returns -1;

  bool pre_verify();
  // Effects: Performs preliminary verification checks

private:
  Fetch_rep& rep() const;
  // Effects: Casts contents to a Fetch_rep&
};

inline Fetch_rep& Fetch::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Fetch_rep*)msg);
}

inline Request_id Fetch::request_id() const
{
  return rep().rid;
}

inline Seqno Fetch::last_uptodate() const
{
  return rep().lu;
}

inline int Fetch::level() const
{
  return rep().level;
}

inline size_t Fetch::index() const
{
  return rep().index;
}

inline int Fetch::id() const
{
  return rep().id;
}

inline Seqno Fetch::checkpoint() const
{
  return rep().rc;
}

inline int Fetch::replier() const
{
  return rep().repid;
}
