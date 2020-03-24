// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "Message.h"
#include "Principal.h"
#include "types.h"

//
// Query_stable messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Query_stable_rep : public Message_rep
{
  int id; // id of the replica that generated the message.
  int nonce;
  // Followed by a variable-sized signature.
};
#pragma pack(pop)

static_assert(
  sizeof(Query_stable_rep) + pbft_max_signature_size < Max_message_size,
  "Invalid size");

class Query_stable : public Message
{
  //
  //  Query_stable messages
  //
public:
  Query_stable(uint32_t msg_size = 0) : Message(msg_size) {}

  Query_stable();
  // Effects: Creates a new authenticated Query_stable message.

  void re_authenticate(Principal* p = 0);
  // Effects: Recomputes the authenticator in the message using the
  // most recent keys.

  int id() const;
  // Effects: Fetches the identifier of the replica from the message.

  int nonce() const;
  // Effects: Fetches the nonce in the message.

  bool verify();
  // Effects: Verifies if the message is signed by the replica rep().id.

  static bool convert(Message* m1, Query_stable*& m2);
  // Effects: If "m1" has the right size and tag of a "Query_stable",
  // casts "m1" to a "Query_stable" pointer, returns the pointer in
  // "m2" and returns true. Otherwise, it returns false. Convert also
  // trims any surplus storage from "m1" when the conversion is
  // successfull.

private:
  Query_stable_rep& rep() const;
  // Effects: Casts "msg" to a Query_stable_rep&
};

inline Query_stable_rep& Query_stable::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Query_stable_rep*)msg);
}

inline int Query_stable::id() const
{
  return rep().id;
}

inline int Query_stable::nonce() const
{
  return rep().nonce;
}
