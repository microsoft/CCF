// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "new_view.h"

#include "message_tags.h"
#include "pbft_assert.h"
#include "principal.h"
#include "replica.h"

#include <string.h>

New_view::New_view(View v) : Message(New_view_tag, Max_message_size)
{
  rep().v = v;
  rep().min = -1;
  rep().max = -1;

  // Initialize vc_info
  for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
  {
    vc_info()[i].d.zero();
  }
}

void New_view::add_view_change(int id, Digest& d)
{
  PBFT_ASSERT(pbft::GlobalState::get_node().is_replica(id), "Not a replica");
  PBFT_ASSERT(vc_info()[id].d == Digest(), "Duplicate");

  VC_info& vci = vc_info()[id];
  vci.d = d;
}

void New_view::set_min(Seqno min)
{
  PBFT_ASSERT(rep().min == -1, "Invalid state");
  rep().min = min;
}

void New_view::set_max(Seqno max)
{
  PBFT_ASSERT(min() >= 0, "Invalid state");
  rep().max = max;
  PBFT_ASSERT(max >= min() && max - min() <= max_out + 1, "Invalid arguments");
}

void New_view::pick(int id, Seqno n)
{
  PBFT_ASSERT(min() >= 0, "Invalid state");
  PBFT_ASSERT(pbft::GlobalState::get_node().is_replica(id), "Not a replica");
  PBFT_ASSERT(vc_info()[id].d != Digest(), "Invalid argument");
  PBFT_ASSERT(n >= min() && n <= min() + max_out, "Invalid argument");

  picked()[n - min()] = (uint8_t)id;
}

bool New_view::view_change(int id, Digest& d)
{
  if (id < 0 || id >= pbft::GlobalState::get_node().num_of_replicas())
  {
    return false;
  }

  VC_info& vci = vc_info()[id];
  if (vci.d.is_zero())
  {
    return false;
  }

  d = vci.d;

  return true;
}

bool New_view::pre_verify()
{
  if (
    view() <= 0 || min() < 0 || max() < 0 || max() < min() ||
    max() - min() > max_out + 1)
  {
    return false;
  }

  // Check that each entry in picked is set to the identifier of a replica
  // whose view-change digest is in this.
  for (Seqno i = min(); i < max(); i++)
  {
    int vci = picked()[i - min()];
    if (
      !pbft::GlobalState::get_node().is_replica(vci) ||
      vc_info()[vci].d.is_zero())
    {
      return false;
    }
  }

  int old_size = sizeof(New_view_rep) +
    sizeof(VC_info) * pbft::GlobalState::get_node().num_of_replicas() + max() -
    min();

  if (Max_message_size - old_size < pbft_max_signature_size)
  {
    return false;
  }

  return true;
}
