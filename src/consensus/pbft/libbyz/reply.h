// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "digest.h"
#include "message.h"
#include "types.h"

class Principal;
class Rep_info;

//
// Reply messages have the following format.
//
#pragma pack(push)
#pragma pack(1)
struct Reply_rep : public Message_rep
{
  View v; // current view
  Request_id rid; // unique request identifier
  Seqno n; // sequence number when request was executed
  uint64_t nonce; // plain text pre-prepare or prepare nonce that will be sent
                  // to the client
  int replica; // id of replica sending the reply
  int reply_size; // if negative, reply is not full.
  // Followed by a reply that is "reply_size" bytes long and
  // a MAC authenticating the reply to the client. The MAC is computed
  // only over the Reply_rep. Replies can be empty or full. Full replies
  // contain the actual reply and have reply_size >= 0. Empty replies
  // do not contain the actual reply and have reply_size < 0.
};
#pragma pack(pop)
static_assert(
  sizeof(Reply_rep) + pbft_max_signature_size < Max_message_size,
  "Invalid size");

class Reply : public Message
{
  //
  // Reply messages
  //
public:
  Reply() : Message() {}

  Reply(uint32_t msg_size) : Message(msg_size) {}

  Reply(Reply_rep* r);

  Reply(
    View view,
    Request_id req,
    Seqno n,
    uint64_t nonce,
    int replica,
    uint32_t reply_size);
  // Effects: Creates a new (full) Reply message with an empty reply and no
  // authentication. The method store_reply and authenticate should
  // be used to finish message construction.

  Reply* copy(int id) const;
  // Effects: Creates a new object with the same state as this but
  // with replica identifier "id"

  char* store_reply(int& max_len);
  // Effects: Returns a pointer to the location within the message
  // where the reply should be stored and sets "max_len" to the number of
  // bytes available to store the reply. The caller can copy any reply
  // with length less than "max_len" into the returned buffer.

  void authenticate(Principal* p, int act_len, bool tentative);
  // Effects: Terminates the construction of a reply message by
  // setting the length of the reply to "act_len", appending a MAC,
  // and trimming any surplus storage.

  void re_authenticate(Principal* p);
  // Effects: Recomputes the authenticator in the reply using the most
  // recent key.

  Reply(
    View view,
    Request_id req,
    Seqno n,
    uint64_t nonce,
    int replica,
    Principal* p,
    bool tentative);
  // Effects: Creates a new empty Reply message and appends a MAC for principal
  // "p".

  void commit(Principal* p);
  // Effects: If this is tentative converts this into an identical
  // committed message authenticated for principal "p".  Otherwise, it
  // does nothing.

  View view() const;
  // Effects: Fetches the view from the message

  Request_id request_id() const;
  // Effects: Fetches the request identifier from the message.

  Seqno seqno() const;
  // Effects: Returns the sequence number when the request was executed

  int id() const;
  // Effects: Fetches the replier's identifier from the message.

  char* reply(int& len);
  // Effects: Returns a pointer to the reply and sets len to the
  // reply size.

  bool full() const;
  // Effects: Returns true iff "this" is a full reply.

  bool pre_verify();
  // Effects: Performs preliminary verification checks

  bool match(Reply* r);
  // Effects: Returns true if the replies match.

  bool is_tentative() const;
  // Effects: Returns true iff the reply is tentative.

private:
  Reply_rep& rep() const;
  // Effects: Casts "msg" to a Reply_rep&

  friend class Rep_info;
  friend class Rep_info_exactly_once;
};

inline Reply_rep& Reply::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Reply_rep*)msg);
}

inline View Reply::view() const
{
  return rep().v;
}

inline Request_id Reply::request_id() const
{
  return rep().rid;
}

inline Seqno Reply::seqno() const
{
  return rep().n;
}

inline int Reply::id() const
{
  return rep().replica;
}

inline char* Reply::reply(int& len)
{
  len = rep().reply_size;
  return contents() + sizeof(Reply_rep);
}

inline bool Reply::full() const
{
  return rep().reply_size >= 0;
}

inline bool Reply::is_tentative() const
{
  return rep().extra;
}

inline bool Reply::match(Reply* r)
{
  if (r == nullptr)
  {
    return false;
  }

  return (rep().n == r->rep().n) &
    ((!is_tentative() & !r->is_tentative()) | (view() == r->view()));
}
