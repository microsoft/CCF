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
// View_change_ack messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct View_change_ack_rep : public Message_rep
{
  View v;
  int id;
  int vcid;
  Digest vcd;
  // Followed by a MAC for the intended recipient
};
#pragma pack(pop)

static_assert(
  sizeof(View_change_ack_rep) + pbft_max_signature_size < Max_message_size,
  "Invalid size");

class View_change_ack : public Message
{
  //
  // View_change_ack messages
  //
public:
  View_change_ack(uint32_t msg_size = 0) : Message(msg_size) {}

  View_change_ack(View v, int id, int vcid, Digest const& vcd);
  // Effects: Creates a new authenticated View_change_ack message for
  // replica "id" stating that replica "vcid" sent out a view-change
  // message for view "v" with digest "vcd". The MAC is for the primary
  // of "v".

  void re_authenticate(Principal* p = 0);
  // Effects: Recomputes the MAC in the message using the
  // most recent keys. If "p" is not null, computes a MAC for "p"
  // rather than for the primary of "view()".

  View view() const;
  // Effects: Fetches the view number from the message.

  int id() const;
  // Effects: Fetches the identifier of the replica from the message.

  int vc_id() const;
  // Effects: Fetches the identifier of the replica whose view-change
  // message is being acked.

  Digest& vc_digest() const;
  // Effects: Fetches the digest of the view-change message that is
  // being acked.

  bool match(const View_change_ack* p) const;
  // Effects: Returns true iff "p" and "this" match.

  bool verify();
  // Effects: Verifies if the message is signed by the replica rep().id.

private:
  View_change_ack_rep& rep() const;
  // Effects: Casts contents to a View_change_ack_rep&
};

inline View_change_ack_rep& View_change_ack::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((View_change_ack_rep*)msg);
}

inline View View_change_ack::view() const
{
  return rep().v;
}

inline int View_change_ack::id() const
{
  return rep().id;
}

inline int View_change_ack::vc_id() const
{
  return rep().vcid;
}

inline Digest& View_change_ack::vc_digest() const
{
  return rep().vcd;
}

inline bool View_change_ack::match(const View_change_ack* p) const
{
  PBFT_ASSERT(view() == p->view(), "Invalid argument");
  return vc_id() == p->vc_id() && vc_digest() == p->vc_digest();
}
