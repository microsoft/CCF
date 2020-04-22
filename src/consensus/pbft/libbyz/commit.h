// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "message.h"
#include "types.h"
class Principal;

//
// Commit messages have the following format.
//
#pragma pack(push)
#pragma pack(1)
struct Commit_rep : public Message_rep
{
  View view;
  Seqno seqno;
  int id; // id of the replica that generated the message.
  int padding;
  // Followed by a variable-sized signature.
};
#pragma pack(pop)
static_assert(
  sizeof(Commit_rep) + pbft_max_signature_size < Max_message_size,
  "Invalid size");

class Commit : public Message
{
  //
  // Commit messages
  //
public:
  Commit(uint32_t msg_size = 0) : Message(msg_size) {}

  Commit(View v, Seqno s);
  // Effects: Creates a new Commit message with view number "v"
  // and sequence number "s".

  Commit(Commit_rep* contents);
  // Requires: "contents" contains a valid Commit_rep. If
  // contents may not be a valid Commit_rep use the static
  // method convert.
  // Effects: Creates a Commit message from "contents". No copy
  // is made of "contents" and the storage associated with "contents"
  // is not deallocated if the message is later deleted.

  void re_authenticate(Principal* p = 0);
  // Effects: Recomputes the authenticator in the message using the
  // most recent keys. If "p" is not null, may only update "p"'s
  // entry.

  View view() const;
  // Effects: Fetches the view number from the message.

  Seqno seqno() const;
  // Effects: Fetches the sequence number from the message.

  int id() const;
  // Effects: Fetches the identifier of the replica from the message.

  bool match(const Commit* c) const;
  // Effects: Returns true iff this and c match.

  bool pre_verify();
  // Effects: Performs preliminary verification checks

  static bool convert(char* m1, unsigned max_len, Commit& m2);
  // Requires: convert can safely read up to "max_len" bytes starting
  // at "m1".
  // Effects: If "m1" has the right size and tag of a
  // "Commit_rep" assigns the corresponding Commit to m2 and
  // returns true.  Otherwise, it returns false.  No copy is made of
  // m1 and the storage associated with "contents" is not deallocated
  // if "m2" is later deleted.

private:
  Commit_rep& rep() const;
  // Effects: Casts "msg" to a Commit_rep&
};

inline Commit_rep& Commit::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Commit_rep*)msg);
}

inline View Commit::view() const
{
  return rep().view;
}

inline Seqno Commit::seqno() const
{
  return rep().seqno;
}

inline int Commit::id() const
{
  return rep().id;
}

inline bool Commit::match(const Commit* c) const
{
  PBFT_ASSERT(view() == c->view() && seqno() == c->seqno(), "Invalid argument");
  return true;
}
