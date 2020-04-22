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
// Checkpoint messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Checkpoint_rep : public Message_rep
{
  Seqno seqno;
  Digest digest;
  int id; // id of the replica that generated the message.
#ifdef USE_PKEY_CHECKPOINTS
  size_t sig_size;
#endif
  int padding;
  // Followed by a variable-sized signature.
};
#pragma pack(pop)

static_assert(
  sizeof(Checkpoint_rep) + pbft_max_signature_size < Max_message_size,
  "Invalid size");

class Checkpoint : public Message
{
  //
  //  Checkpoint messages
  //
public:
  Checkpoint(uint32_t msg_size = 0) : Message(msg_size) {}

  Checkpoint(Seqno s, Digest& d, bool stable = false);
  // Effects: Creates a new signed Checkpoint message with sequence
  // number "s" and digest "d". "stable" should be true iff the checkpoint
  // is known to be stable.

  void re_authenticate(Principal* p = 0, bool stable = false);
  // Effects: Recomputes the authenticator in the message using the
  // most recent keys. "stable" should be true iff the checkpoint is
  // known to be stable.  If "p" is not null, may only update "p"'s
  // entry.

  Seqno seqno() const;
  // Effects: Fetches the sequence number from the message.

  int id() const;
  // Effects: Fetches the identifier of the replica from the message.

  Digest& digest() const;
  // Effects: Fetches the digest from the message.

  bool stable() const;
  // Effects: Returns true iff the sender of the message believes the
  // checkpoint is stable.

  bool match(const Checkpoint* c) const;
  // Effects: Returns true iff "c" and "this" have the same digest

  bool pre_verify();
  // Effects: Performs preliminary verification checks

private:
  Checkpoint_rep& rep() const;
  // Effects: Casts "msg" to a Checkpoint_rep&
};

inline Checkpoint_rep& Checkpoint::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Checkpoint_rep*)msg);
}

inline Seqno Checkpoint::seqno() const
{
  return rep().seqno;
}

inline int Checkpoint::id() const
{
  return rep().id;
}

inline Digest& Checkpoint::digest() const
{
  return rep().digest;
}

inline bool Checkpoint::stable() const
{
  return rep().extra == 1;
}

inline bool Checkpoint::match(const Checkpoint* c) const
{
  PBFT_ASSERT(seqno() == c->seqno(), "Invalid argument");
  return digest() == c->digest();
}
