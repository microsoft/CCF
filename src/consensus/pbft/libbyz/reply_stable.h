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
// Reply_stable messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Reply_stable_rep : public Message_rep
{
  Seqno lc; // last checkpoint at sending replica
  Seqno lp; // last prepared request at sending replica
  int id; // id of sending replica
  int nonce; // nonce in query-stable
  // Followed by a MAC
};
#pragma pack(pop)

static_assert(
  sizeof(Reply_stable_rep) + pbft_max_signature_size < Max_message_size,
  "Invalid size");

class Reply_stable : public Message
{
  //
  //  Reply_stable messages
  //
public:
  Reply_stable(uint32_t msg_size = 0) : Message(msg_size) {}

  Reply_stable(Seqno lc, Seqno lp, int n, Principal* p);
  // Effects: Creates a new authenticated Reply_stable message with
  // last checkpoint "lc", last prepared request "lp", for a
  // query-stable with nonce "n" from principal "p".

  void re_authenticate(Principal* p);
  // Effects: Recomputes the MAC in the message using the most recent
  // keys.

  Seqno last_checkpoint() const;
  // Effects: Fetches the sequence number of the last checkpoint from
  // the message.

  Seqno last_prepared() const;
  // Effects: Fetches the sequence number of the last prepared request
  // from the message.

  int id() const;
  // Effects: Fetches the identifier of the sender from the message.

  int nonce() const;
  // Effects: Fetches the nonce of the query from the message.

  bool verify();
  // Effects: Verifies if the message is authenticated by "id()".

private:
  Reply_stable_rep& rep() const;
  // Effects: Casts "msg" to a Reply_stable_rep&
};

inline Reply_stable_rep& Reply_stable::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Reply_stable_rep*)msg);
}

inline Seqno Reply_stable::last_checkpoint() const
{
  return rep().lc;
}

inline Seqno Reply_stable::last_prepared() const
{
  return rep().lp;
}

inline int Reply_stable::id() const
{
  return rep().id;
}

inline int Reply_stable::nonce() const
{
  return rep().nonce;
}
