// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "Digest.h"
#include "Message.h"
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
  sizeof(Reply_stable_rep) + max_sig_size < Max_message_size, "Invalid size");

class Reply_stable : public Message
{
  //
  //  Reply_stable messages
  //
public:
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

  static bool convert(Message* m1, Reply_stable*& m2);
  // Effects: If "m1" has the right size and tag of a "Reply_stable",
  // casts "m1" to a "Reply_stable" pointer, returns the pointer in
  // "m2" and returns true. Otherwise, it returns false. Convert also
  // trims any surplus storage from "m1" when the conversion is
  // successfull.

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
