// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "bits.h"
#include "digest.h"
#include "message.h"
#include "parameters.h"
#include "principal.h"
#include "types.h"

//
// Req_infos describe requests that (1) prepared or (2) for which a
// pre-prepare/prepare message was sent.
//
// In case (1):
// - the request with digest "digest" prepared in view "view" with
// sequence number "n";
// - no request prepared with the same sequence number in a later
// view; and
// - the last pre-prepare/prepare sent by the replica for this request
// was for view "last_sent_view".
//
// In case (2):
// - a pre-prepare/prepare was sent for a request with digest "digest" in
// view "view" with sequence number "n"; and
// - no request prepared globally with sequence number "n" in any view
// "view' <= last_sent_view".
//

#pragma pack(push)
#pragma pack(1)
struct Req_info
{
  View last_sent_view;
  View view;
  Digest digest;
};

//
// View_change messages have the following format:
//
struct View_change_rep : public Message_rep
{
  View view; // sending replica's new view
  // sequence number of last checkpoint known to be stable
  Seqno last_stable_ckpt;

  // Digests for checkpoints held by the replica in order of
  // increasing sequence number. A null digest means the replica does
  // not have the corresponding checkpoint state.
  Digest ckpts[max_out / checkpoint_interval + 1];

  int id; // sending replica's id

  short n_ckpts; // number of entries in ckpts
  short n_reqs; // number of entries in req_info

  // Bitmap with bits set for requests that are prepared in req_info
  std::bitset<max_out> prepared;

  // digest of the entire message (except authenticator) with d zeroed.
  Digest digest;

#ifdef SIGN_BATCH
  size_t digest_sig_size;
  // signature of the digest of the entire message.
  PbftSignature digest_signature;
  static constexpr size_t padding_size =
    ALIGNED_SIZE(pbft_max_signature_size) - pbft_max_signature_size;
  std::array<uint8_t, padding_size> padding;
#endif

#ifdef USE_PKEY_VIEW_CHANGES
  size_t vc_sig_size;
#endif

  /*
     Followed by:
     Req_info req_info[n_reqs];

     // This is followed by an authenticator from principal id.
   */
};
#pragma pack(pop)

static_assert(
  sizeof(View_change_rep) + sizeof(Req_info) * max_out +
      pbft_max_signature_size <
    Max_message_size,
  "Invalid size");

class View_change : public Message
{
  //
  //  View_change messages
  //
public:
  View_change(uint32_t msg_size = 0) : Message(msg_size) {}

  View_change(View v, Seqno ls, int id);
  // Effects: Creates a new (unauthenticated) View_change message for
  // replica "id" in view "v". The message states that "ls" is the
  // sequence number of the last checkpoint known to be stable but the
  // message has an empty set of requests and checkpoints.

  void add_checkpoint(Seqno n, Digest& d);
  // Requires: "n%checkpoint_interval = 0", and "last_stable() <= n <=
  // last_stable()+max_out".
  // Effects: Sets the digest of the checkpoint with sequence number
  // "n" to "d".

  void add_request(Seqno n, View v, View lv, Digest& d, bool prepared);
  // Requires: "last_stable() < n <= last_stable()+max_out".
  // Effects: Sets the Req_info for the request with sequence number
  // "n" to "{lv, v, d}" and records whether the request is prepared.

  int id() const;
  // Effects: Fetches the identifier of the replica from the message.

  View view() const;
  // Effects: Returns the view in the message.

  Digest& digest();
  // Effects: Returns the digest of this message (excluding the
  // authenticator).

#ifdef SIGN_BATCH
  PbftSignature& signature();
#endif

  Seqno last_stable() const;
  // Effects: Returns the sequence number of the last stable
  // checkpoint.

  Seqno max_seqno() const;
  // Effects: Returns the maximum sequence number refered to in this.

  bool last_ckpt(Digest& d, Seqno& n);
  // Effects: If this contains some checkpoint digest, returns true
  // and sets "d" to the digest of the checkpoint with the highest
  // sequence number "n" int this.

  bool ckpt(Seqno n, Digest& d);
  // Effects: If there is a checkpoint with sequence number "n" in the
  // message, sets "d" to its digest and returns true. Otherwise,
  // returns false without modifying "d".

  bool proofs(Seqno n, View& v, View& lv, Digest& d, bool& prepared);
  // Effects: If there is a request with sequence number "n" in the
  // message, sets "v, lv", and "d" to the values in the request's
  // Req_info, sets prepared to true iff the request is prepared and
  // returns true. Otherwise, returns false without other effects.

  View req(Seqno n, Digest& d);
  // Requires: n > last_stable()
  // Effects: Returns the view and sets "d" to the digest associated with
  // the request with sequence number "n" in the message.

  void re_authenticate(Principal* p = 0);
  // Effects: Recomputes the authenticator in the message using the
  // most recent keys. If "p" is not null, may only update "p"'s
  // entry in the authenticator.

  bool pre_verify();
  // Effects: Performs preliminary verification checks

  bool verify_digest();
  // Effects: Returns true iff digest() is correct.

private:
  View_change_rep& rep() const;
  // Effects: Casts "msg" to a View_change_rep&

  Req_info* req_info();
  // Effects: Returns a pointer to the prep_info array.

  void mark(int i);
  // Effects: Marks request with index i (sequence number
  // "i+last_stable+1") prepared.

  bool test(int i);
  // Effects: Returns true iff the request with index i (sequence
  // number "i+last_stable+1") is prepared.
};

inline View_change_rep& View_change::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((View_change_rep*)msg);
}

inline Req_info* View_change::req_info()
{
  Req_info* ret = (Req_info*)(contents() + sizeof(View_change_rep));
  return ret;
}

inline void View_change::mark(int index)
{
  PBFT_ASSERT(index >= 0 && index < rep().prepared.size(), "Out of bounds");
  rep().prepared.set(index);
}

inline bool View_change::test(int index)
{
  PBFT_ASSERT(index >= 0 && index < rep().prepared.size(), "Out of bounds");
  return rep().prepared.test(index);
}

inline int View_change::id() const
{
  return rep().id;
}

inline View View_change::view() const
{
  return rep().view;
}

inline Digest& View_change::digest()
{
  return rep().digest;
}

#ifdef SIGN_BATCH
inline PbftSignature& View_change::signature()
{
  return rep().digest_signature;
}
#endif

inline Seqno View_change::last_stable() const
{
  return rep().last_stable_ckpt;
}

inline Seqno View_change::max_seqno() const
{
  return rep().last_stable_ckpt + rep().n_reqs;
}

inline bool View_change::last_ckpt(Digest& d, Seqno& n)
{
  if (rep().n_ckpts > 0)
  {
    d = rep().ckpts[rep().n_ckpts - 1];
    n = (rep().n_ckpts - 1) * checkpoint_interval + rep().last_stable_ckpt;
    PBFT_ASSERT(d != Digest(), "Invalid state");

    return true;
  }

  return false;
}
