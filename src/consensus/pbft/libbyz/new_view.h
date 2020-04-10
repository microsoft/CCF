// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "digest.h"
#include "message.h"
#include "node.h"
#include "types.h"

//
// New_view messages have the following format:
//

#pragma pack(push)
#pragma pack(1)
// Structure describing view-change message
struct VC_info
{
  Digest d; // digest of view-change message
};

struct New_view_rep : public Message_rep
{
  View v;

  Seqno min; // Sequence number of checkpoint chosen for propagation.
  Seqno max; // All requests that will be propagated to the next view
             // have sequence number less than max

  /* Followed by:

     // vc_info has information about view-changes selected by primary
     // to form the new view. It has an entry for every replica and is
     // indexed by replica identifier. If a replica's entry has a null
     // digest, its view-change is not part of those selected to form
     // the new-view.
     VC_info vc_info[pbft::GlobalState::get_node().num_of_replicas()];

     // picked contains identifiers of replicas from whose view-change
     // message a checkpoint value or request was picked for propagation
     // to the new view. It is indexed by sequence number minus min.
     uint8_t picked[max-min];

     // The rationale for including just view-change digests rather
     // than the full messages is that most of the time replicas will
     // receive the view-change messages referenced by the new-view
     // message before they receive the new-view.

     // This is all followed by an authenticator.
   */
};
#pragma pack(pop)

static_assert(Max_num_replicas <= UINT8_MAX, "Invalid Max_num_replicas");
static_assert(
  sizeof(New_view_rep) + sizeof(VC_info) * Max_num_replicas +
      sizeof(uint8_t) * max_out + pbft_max_signature_size <
    Max_message_size,
  "Invalid size");

class New_view : public Message
{
  //
  //  New_view messages
  //
public:
  New_view(uint32_t msg_size = 0) : Message(msg_size) {}

  New_view(View v);
  // Effects: Creates a new (unsigned) New_view message with an empty
  // set of view change messages.

  void add_view_change(int id, Digest& d);
  // Requires: Only one view-change per id may be added and id must be
  // a valid replica id.
  // Effects: Adds information to the set of view changes in this.

  void set_min(Seqno min);
  // Effects: Record that "min" is the sequence number of the
  // checkpoint that will be propagated to the new view.

  void set_max(Seqno max);
  // Effects: Record that all requests that will propagate to the new
  // view have sequence number less than max.

  void pick(int id, Seqno n);
  // Requires: A view-change message "m" for replica "id" has been added
  // to this such that m.last_stable() <= n <= m.last_stable()+max_out
  // Effects: Mark the request (or checkpoint) with sequence number
  // "n" in "m" as picked (i.e., chosen to be propagated into the next
  // view.)

  View view() const;
  // Effects: Returns the view in the message.

  int id() const;
  // Effects: Returns the identifier of the primary for "view()"

  Seqno min() const;
  // Effects: Returns the sequence number of the checkpoint picked to
  // propagate to new view.

  Seqno max() const;
  // Effects: Returns a sequence number such that all requests that
  // will propagate to new-view have sequence number less than max().

  bool view_change(int id, Digest& d);
  // Effects: If there is a view-change message from replica "id" in
  // this, sets "d" to its digest and returns true. Otherwise, it
  // returns false.

  bool view_change(int id);
  // Requires: id >= 0 && id < pbft::GlobalState::get_node().num_of_replicas())
  // Effects: Same as view_change(int id, Digest& d) but does not set
  // digest.

  int which_picked(Seqno n);
  // Effects: Returns the identifier of the replica whose view-change
  // message information for sequence number "n" was picked for
  // propagation to the new-view.

  bool pre_verify();
  // Effects: Performs preliminary verification checks

private:
  New_view_rep& rep() const;
  // Effects: Casts "msg" to a New_view_rep&

  VC_info* vc_info();
  // Effects: Returns a pointer to the vc_info array.

  uint8_t* picked();
  // Effects: Returns a pointer to the picked array.
};

inline New_view_rep& New_view::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((New_view_rep*)msg);
}

inline VC_info* New_view::vc_info()
{
  VC_info* ret = (VC_info*)(contents() + sizeof(New_view_rep));
  return ret;
}

inline uint8_t* New_view::picked()
{
  // Effects: Returns a pointer to the picked array.
  return (
    uint8_t*)(vc_info() + pbft::GlobalState::get_node().num_of_replicas());
}

inline View New_view::view() const
{
  return rep().v;
}

inline int New_view::id() const
{
  return pbft::GlobalState::get_node().primary(view());
}

inline Seqno New_view::min() const
{
  return rep().min;
}

inline Seqno New_view::max() const
{
  return rep().max;
}

inline int New_view::which_picked(Seqno n)
{
  PBFT_ASSERT(n >= min() && n < max(), "Invalid argument");
  return (int)picked()[n - min()];
}

inline bool New_view::view_change(int id)
{
  VC_info& vci = vc_info()[id];
  if (vci.d.is_zero())
    return false;
  return true;
}
