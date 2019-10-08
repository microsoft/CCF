// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "Digest.h"
#include "Message.h"
#include "keypair.h"
#include "types.h"

class Principal;

//
// Prepare messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Prepare_rep : public Message_rep
{
  View view;
  Seqno seqno;
  Digest digest;
  int id; // id of the replica that generated the message.

#ifdef SIGN_BATCH
  KeyPair::Signature batch_digest_signature;
#endif

  int padding;
  // Followed by a variable-sized signature.
};
#pragma pack(pop)

static_assert(
  sizeof(Prepare_rep) + max_sig_size < Max_message_size, "Invalid size");

class Prepare : public Message
{
  //
  // Prepare messages
  //
public:
  Prepare(View v, Seqno s, Digest& d, Principal* dst = 0);
  // Effects: Creates a new signed Prepare message with view number
  // "v", sequence number "s" and digest "d". "dst" should be non-null
  // iff prepare is sent to a single replica "dst" as proof of
  // authenticity for a request.

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

  Digest& digest() const;
  // Effects: Fetches the digest from the message.

#ifdef SIGN_BATCH
  std::array<uint8_t, signature_size>& digest_sig() const;
#endif

  bool is_proof() const;
  // Effects: Returns true iff this was sent as proof of authenticity
  // for a request.

  bool match(const Prepare* p) const;
  // Effects: Returns true iff "p" and "this" match.

  bool verify();
  // Effects: Verifies if the message is signed by the replica rep().id.

  bool pre_verify();
  // Effects: Performs preliminary verification checks

  static bool convert(Message* m1, Prepare*& m2);
  // Effects: If "m1" has the right size and tag, casts "m1" to a
  // "Prepare" pointer, returns the pointer in "m2" and returns
  // true. Otherwise, it returns false.

private:
  Prepare_rep& rep() const;
  // Effects: Casts contents to a Prepare_rep&
};

inline Prepare_rep& Prepare::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Prepare_rep*)msg);
}

inline View Prepare::view() const
{
  return rep().view;
}

inline Seqno Prepare::seqno() const
{
  return rep().seqno;
}

inline int Prepare::id() const
{
  return rep().id;
}

inline Digest& Prepare::digest() const
{
  return rep().digest;
}

#ifdef SIGN_BATCH
inline std::array<uint8_t, signature_size>& Prepare::digest_sig() const
{
  return rep().batch_digest_signature;
}
#endif

inline bool Prepare::is_proof() const
{
  return rep().extra != 0;
}

inline bool Prepare::match(const Prepare* p) const
{
  PBFT_ASSERT(view() == p->view() && seqno() == p->seqno(), "Invalid argument");
  return digest() == p->digest();
}
