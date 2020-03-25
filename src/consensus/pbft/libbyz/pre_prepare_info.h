// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "pre_prepare.h"
#include "types.h"

class Pre_prepare_info
{
  //
  // Holds information about a pre-prepare and matching big requests.
  //
public:
  Pre_prepare_info();
  // Effects: Creates an empty object.

  ~Pre_prepare_info();
  // Effects: Discard this and any pre-prepare message it may contain.

  void add(Pre_prepare* p);
  // Effects: Adds "p" to this.

  void add_complete(Pre_prepare* p);
  // Effects: Adds "p" to this and records that all the big reqs it
  // refers to are cached.

  void add(Digest& rd, int i);
  // Effects: If there is a pre-prepare in this and its i-th reference
  // to a big request is for the request with digest rd record that
  // this digest is cached.

  Pre_prepare* pre_prepare() const;
  // Effects: If there is a pre-prepare message in this returns
  // it. Otherwise, returns 0.

  const BR_map& missing_reqs() const;
  // Effects: Returns a bit map with the indices of missing requests.

  bool is_complete() const;
  // Effects: Returns true iff this contains a pre-prepare and all the
  // big requests it references are cached.

  void clear();
  // Effects: Makes this empty and deletes any pre-prepare in it.

  void zero();
  // Effects: Makes this empty without deleting any contained
  // pre-prepare.

  class BRS_iter
  {
    // An iterator for yielding the requests in ppi that are missing
    // in mrmap.
  public:
    BRS_iter(Pre_prepare_info const* p, const BR_map& m);
    // Effects: Return an iterator for the missing requests in mrmap

    bool get(Request*& r);
    // Effects: Sets "r" to the next request in this that is missing
    // in mrmap, and returns true. Unless there are no more missing
    // requests in this, in which case it returns false.

  private:
    Pre_prepare_info const* ppi;
    BR_map mrmap;
    int next;
  };
  friend class BRS_iter;

  void dump_state(std::ostream& os);
  // Effects: logs state for debugging

private:
  Pre_prepare* pp;
  short mreqs; // Number of missing requests
  BR_map mrmap; // Bitmap with bit reset for every missing request
};

inline Pre_prepare_info::Pre_prepare_info()
{
  pp = 0;
}

inline void Pre_prepare_info::zero()
{
  pp = 0;
}

inline void Pre_prepare_info::add_complete(Pre_prepare* p)
{
  PBFT_ASSERT(pp == 0, "Invalid state");
  pp = p;
  mreqs = 0;
  mrmap.set();
}

inline Pre_prepare* Pre_prepare_info::pre_prepare() const
{
  return pp;
}

inline const BR_map& Pre_prepare_info::missing_reqs() const
{
  return mrmap;
}

inline void Pre_prepare_info::clear()
{
  delete pp;
  pp = 0;
  mrmap.reset();
}

inline bool Pre_prepare_info::is_complete() const
{
  return pp != 0 && mreqs == 0;
}
