// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "digest.h"
#include "parameters.h"
#include "types.h"

#include <sys/time.h>

class Meta_data_d;

class Meta_data_cert
{
  //
  // A Meta_data_cert is a set of "matching" meta-data-d messages from
  // different replicas.
  //

public:
  Meta_data_cert(size_t num_replicas, size_t f);

  Meta_data_cert(size_t num_replicas);
  // Effects: Creates an empty Meta_data_cert.

  ~Meta_data_cert();
  // Effects: Deletes Meta_data_cert and all the messages it contains.

  bool add(Meta_data_d* m, bool mine = false);
  // Effects: Adds "m" to the Meta_data_cert and returns true provided
  // "m" satisfies:
  // 1. there is no message from "m->id()" in the this or, if there is
  // such a message "m1", "m1->last_checkpoint() < m->last_checkpoint()"
  // 2. "m->verify() == true"
  // Otherwise, it has no effect on this and returns false.  This
  // becomes the owner of "m" (i.e., no other code should delete "m"
  // or retain pointers to "m").

  bool has_mine() const;
  // Effects: Returns true iff my message is in this

  bool cvalue(Seqno& c, Digest& d) const;
  // Effects: Returns true if a correct digest value was found and
  // sets "d" to the digest value and "c" to the sequence number of
  // the checkpoint for which that value is known to be up-to-date.
  // Otherwise, returns false.

  Seqno last_stable() const;
  // Effects: Returns the greatest sequence number known to be stable.

  void clear();
  // Effects: Discards all messages in Meta_data_cert

private:
  Seqno* last_stables; // Array with last last_stables in messages
                       // sent by each replica
  Seqno ls;

  Meta_data_d** last_mdds; // Array with the last messages sent by each
                           // replica.
  class Part_val
  {
  public:
    Digest d;
    Seqno c;
    int count;

    inline Part_val()
    {
      clear();
    }
    inline void clear()
    {
      c = -1;
      count = 0;
    }
  };
  Part_val* vals; // vector with all distinct part values in this
  int max_size; // maximum number of elements in vals
  int cur_size; // current number of elements in vals

  int correct; // value is correct if it appears in at least "correct" messages

  Seqno c; // If "c >=0", the digest of partition "d" is up-to-date at
  Digest d; // sequence number "c"

  bool has_my_message; // True iff replica's message is in this
  size_t num_replicas;
};

inline bool Meta_data_cert::has_mine() const
{
  return has_my_message;
}

inline bool Meta_data_cert::cvalue(Seqno& ci, Digest& di) const
{
  if (c < 0)
    return false;

  ci = c;
  di = d;
  return true;
}

inline Seqno Meta_data_cert::last_stable() const
{
  return ls;
}
