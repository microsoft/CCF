// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "Digest.h"
#include "Message.h"
#include "Prepare.h"
#include "keypair.h"
#include "types.h"

class Principal;
class Req_queue;
class Request;

//
// Pre_prepare messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Pre_prepare_rep : public Message_rep
{
  View view;
  Seqno seqno;
  std::array<uint8_t, MERKLE_ROOT_SIZE> full_state_merkle_root;
  std::array<uint8_t, MERKLE_ROOT_SIZE> replicated_state_merkle_root;
  int64_t ctx; // a context provided when a the batch is executed
               // the contents are opaque
  Digest digest; // digest of request set concatenated with
                 // big reqs and non-deterministic choices
  int rset_size; // size in bytes of request set
  short n_big_reqs; // number of big requests
  short non_det_size; // size in bytes of non-deterministic choices

#ifdef SIGN_BATCH
  KeyPair::Signature batch_digest_signature;
#endif

  // Followed by "rset_size" bytes of the request set, "n_big_reqs"
  // Digest's, "non_det_size" bytes of non-deterministic choices, and
  // a variable length signature in the above order.
};
#pragma pack(pop)
static_assert(
  sizeof(Pre_prepare_rep) + sizeof(Digest) * Max_requests_in_batch +
      max_sig_size <
    Max_message_size,
  "Invalid size");

class Prepare;

class Pre_prepare : public Message
{
  //
  // Pre_prepare messages
  //
public:
  Pre_prepare(View v, Seqno s, Req_queue& reqs, size_t& requests_in_batch);
  // Effects: Creates a new signed Pre_prepare message with view
  // number "v", sequence number "s", the requests in "reqs" (up to a
  // maximum size) and appropriate non-deterministic choices.  It
  // removes the elements of "reqs" that are included in the message
  // from "reqs" and deletes them.

  char* choices(int& len);
  // Effects: Returns a buffer that can be filled with non-deterministic choices

  Pre_prepare* clone(View v) const;
  // Effects: Creates a new object with the same state as this but view v.

  void re_authenticate(Principal* p = 0);
  // Effects: Recomputes the authenticator in the message using the most
  // recent keys. If "p" is not null, may only update "p"'s
  // entry.

  View view() const;
  // Effects: Fetches the view number from the message.

  Seqno seqno() const;
  // Effects: Fetches the sequence number from the message.

  int id() const;
  // Effects: Returns the identifier of the primary for view() (which is
  // the replica that sent the message if the message is correct.)

  bool match(const Prepare* p) const;
  // Effects: Returns true iff "p" and "this" match.

  Digest& digest() const;
  // Effects: Fetches the digest from the message.

  void set_merkle_roots_and_ctx(
    const std::array<uint8_t, MERKLE_ROOT_SIZE>& full_state_merkle_root,
    const std::array<uint8_t, MERKLE_ROOT_SIZE>& replicated_state_merkle_root,
    int64_t ctx);

  const std::array<uint8_t, MERKLE_ROOT_SIZE>& get_full_state_merkle_root()
    const;
  const std::array<uint8_t, MERKLE_ROOT_SIZE>&
  get_replicated_state_merkle_root() const;

  int64_t get_ctx() const;

  class Requests_iter
  {
    // An iterator for yielding the Requests in a Pre_prepare message.
    // Requires: A Pre_prepare message cannot be modified while it is
    // being iterated on and all the big requests referred to by "m"
    // must be cached.
  public:
    Requests_iter(Pre_prepare* m);
    // Requires: Pre_prepare is known to be valid
    // Effects: Return an iterator for the requests in "m"

    bool get(Request& req);
    // Effects: Updates "req" to "point" to the next request in the
    // Pre_prepare message and returns true. If there are no more
    // requests, it returns false.

    bool get_big_request(Request& req);
    // Effects: Updates "req" to "point" to the next big request in the
    // Pre_prepare message and returns true. If there are no more big
    // requests, it returns false.

    bool get_big_request(Request& req, bool& is_request_present);
    // Effects: Updates "req" to "point" to the next big request in the
    // Pre_prepare message and returns true. If there are no more big
    // requests, it returns false. If the request has not arrived yet
    // is_request_present is set to false

  private:
    Pre_prepare* msg;
    char* next_req;
    int big_req;
  };
  friend class Requests_iter;

#ifdef SIGN_BATCH
  KeyPair::Signature& get_digest_sig() const
  {
    return rep().batch_digest_signature;
  }

  static constexpr uint16_t get_digest_sig_size()
  {
    return sizeof(sizeof(uint8_t) * signature_size);
  }
#endif

  // Maximum number of big reqs in pre-prepares.
  int16_t num_big_reqs() const;
  // Effects: Returns the number of big request digests in this

  Digest& big_req_digest(int i);
  // Requires: 0 <= "i" < "num_big_reqs()"
  // Effects: Returns the digest of the i-th big request in this

  static const int NAC = 1;
  static const int NRC = 2;
  bool verify(int mode = 0);
  // Effects: If "mode == 0", verifies if the message is authenticated
  // by the replica "id()", if the digest is correct, and if the
  // requests are authentic. If "mode == NAC", it performs all checks
  // except that it does not check if the message is authenticated by
  // the replica "id()". If "mode == NRC", it performs all checks
  // except that it does not verify the authenticity of the requests.

  bool pre_verify();
  // Effects: Performs preliminary verification checks

  bool check_digest();
  // Effects: Verifies if the digest is correct.

  bool calculate_digest(Digest& d);
  // Effects: calculates the digest.

  bool set_digest(int64_t signed_version = std::numeric_limits<int64_t>::min());
  // Effects: calculates and sets the digest.

  bool is_signed();
  // Effects: checks if there is a signature over the pre_prepare message

  static bool convert(Message* m1, Pre_prepare*& m2);
  // Effects: If "m1" has the right size and tag, casts "m1" to a
  // "Pre_prepare" pointer, returns the pointer in "m2" and returns
  // true. Otherwise, it returns false.

private:
  Pre_prepare_rep& rep() const;
  // Effects: Casts contents to a Pre_prepare_rep&

  char* requests();
  // Effects: Returns a pointer to the first request contents.

  Digest* big_reqs();
  // Effects: Returns a pointer to the first digest of a big request
  // in this.

  char* non_det_choices();
  // Effects: Returns a pointer to the buffer with non-deterministic
  // choices.
};

inline Pre_prepare_rep& Pre_prepare::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Pre_prepare_rep*)msg);
}

inline char* Pre_prepare::requests()
{
  char* ret = contents() + sizeof(Pre_prepare_rep);
  PBFT_ASSERT(ALIGNED(ret), "Improperly aligned pointer");
  return ret;
}

inline Digest* Pre_prepare::big_reqs()
{
  char* ret = requests() + rep().rset_size;
  PBFT_ASSERT(ALIGNED(ret), "Improperly aligned pointer");
  return (Digest*)ret;
}

inline char* Pre_prepare::non_det_choices()
{
  char* ret = ((char*)big_reqs()) + rep().n_big_reqs * sizeof(Digest);
  PBFT_ASSERT(ALIGNED(ret), "Improperly aligned pointer");
  return ret;
}

inline char* Pre_prepare::choices(int& len)
{
  len = rep().non_det_size;
  return non_det_choices();
}

inline View Pre_prepare::view() const
{
  return rep().view;
}

inline Seqno Pre_prepare::seqno() const
{
  return rep().seqno;
}

inline bool Pre_prepare::match(const Prepare* p) const
{
  PBFT_ASSERT(view() == p->view() && seqno() == p->seqno(), "Invalid argument");
  return digest() == p->digest();
}

inline Digest& Pre_prepare::digest() const
{
  return rep().digest;
}

inline int16_t Pre_prepare::num_big_reqs() const
{
  return rep().n_big_reqs;
}

inline Digest& Pre_prepare::big_req_digest(int i)
{
  PBFT_ASSERT(i >= 0 && i < num_big_reqs(), "Invalid argument");
  return *(big_reqs() + i);
}
