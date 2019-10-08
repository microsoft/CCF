// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Status.h"

#include "Message_tags.h"
#include "Node.h"
#include "Principal.h"
#include "pbft_assert.h"

#include <string.h>

Status::Status(View v, Seqno ls, Seqno le, bool hnvi, bool hnvm) :
  Message(Status_tag, Max_message_size)
{
  rep().extra = (hnvi) ? 1 : 0;
  rep().extra |= (hnvm) ? 2 : 0;
  rep().v = v;
  rep().ls = ls;
  rep().le = le;
  rep().id = node->id();
  rep().brsz = 0;

  if (hnvi)
  {
    // Initialize bitmaps.
    rep().sz = (ls + max_out - le + 7) / 8;
    bzero(prepared(), rep().sz);
    bzero(committed(), rep().sz);
  }
  else
  {
    bzero(vcs(), Status_rep::vcs_size);
    rep().sz = 0;
  }
}

void Status::authenticate()
{
  int old_size = sizeof(Status_rep);
  if (!has_nv_info())
  {
    old_size += Status_rep::vcs_size + rep().sz * sizeof(PP_info);
  }
  else
  {
    old_size += rep().sz * 2 + rep().brsz * sizeof(BR_info);
  }

  set_size(old_size + node->auth_size());
  auth_type = Auth_type::out;
  auth_len = old_size;
  auth_src_offset = 0;
}

bool Status::verify()
{
  return verified_auth;
}

bool Status::pre_verify()
{
  if (!node->is_replica(id()) || id() == node->id() || view() < 0)
  {
    return false;
  }

  // Check size and authenticator
  int old_size = sizeof(Status_rep);
  if (!has_nv_info())
  {
    old_size += Status_rep::vcs_size + rep().sz * sizeof(PP_info);
  }
  else
  {
    old_size += rep().sz * 2 + rep().brsz * sizeof(BR_info);
  }

  if (size() - old_size < node->auth_size(id()))
  {
    return false;
  }

  // Check if message is self consistent
  int diff = rep().le - rep().ls;
  if (diff < 0 || diff > max_out)
  {
    return false;
  }

  if (!has_nv_info())
  {
    if (rep().sz < 0 || rep().sz > max_out)
    {
      return false;
    }
  }
  else
  {
    if (rep().sz != (max_out - diff + 7) / 8)
    {
      return false;
    }
  }

  verified_auth = node->verify_mac_in(id(), contents(), old_size);
  return true;
}

bool Status::convert(Message* m1, Status*& m2)
{
  if (!m1->has_tag(Status_tag, sizeof(Status_rep)))
  {
    return false;
  }

  m1->trim();
  m2 = (Status*)m1;
  return true;
}

void Status::mark_vcs(int i)
{
  PBFT_ASSERT(!has_nv_info(), "Invalid state");
  PBFT_ASSERT(
    i >= 0 && i < Status_rep::vcs_size * BYTE_BITS, "Invalid argument");
  Bits_set(vcs(), i);
}

void Status::append_pps(View v, Seqno n, const BR_map& mreqs, bool proof)
{
  PBFT_ASSERT(!has_nv_info(), "Invalid state");
  PBFT_ASSERT(
    (char*)(pps() + rep().sz) < contents() + Max_message_size,
    "Message too small");

  PP_info& ppi = pps()[rep().sz];
  ppi.n = n - rep().ls;
  ppi.v = v;
  ppi.breqs = mreqs;
  ppi.proof = (proof) ? 1 : 0;
  rep().sz++;
}

Status::PPS_iter::PPS_iter(Status* m)
{
  PBFT_ASSERT(!m->has_nv_info(), "Invalid state");

  msg = m;
  next = 0;
}

bool Status::PPS_iter::get(View& v, Seqno& n, BR_map& mreqs, bool& proof)
{
  if (next < msg->rep().sz)
  {
    PP_info& ppi = msg->pps()[next];
    v = ppi.v;
    n = ppi.n + msg->rep().ls;
    proof = ppi.proof != 0;
    mreqs = ppi.breqs;
    next++;
    return true;
  }

  return false;
}

Status::BRS_iter::BRS_iter(Status* m)
{
  PBFT_ASSERT(m->has_nv_info(), "Invalid state");

  msg = m;
  next = 0;
}

bool Status::BRS_iter::get(Seqno& n, BR_map& mreqs)
{
  if (next < msg->rep().brsz)
  {
    BR_info& bri = msg->breqs()[next];
    n = bri.n;
    mreqs = bri.breqs;
    next++;
    return true;
  }

  return false;
}
