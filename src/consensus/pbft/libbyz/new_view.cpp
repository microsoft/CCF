// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "new_view.h"

#include "ds/ccf_assert.h"
#include "message_tags.h"
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

void New_view::add_view_change(
  int id, Digest& d, PbftSignature& sig, size_t sig_size)
{
  CCF_ASSERT(pbft::GlobalState::get_node().is_replica(id), "Not a replica");
  CCF_ASSERT(vc_info()[id].d == Digest(), "Duplicate");

  VC_info& vci = vc_info()[id];
  vci.d = d;
  Node::copy_signature(sig, vci.sig);
  vci.sig_size = sig_size;
}

void New_view::set_min(Seqno min)
{
  CCF_ASSERT(rep().min == -1, "Invalid state");
  rep().min = min;
}

void New_view::set_max(Seqno max)
{
  CCF_ASSERT(min() >= 0, "Invalid state");
  rep().max = max;
  CCF_ASSERT(max >= min() && max - min() <= max_out + 1, "Invalid arguments");
}

void New_view::pick(int id, Seqno n)
{
  CCF_ASSERT(min() >= 0, "Invalid state");
  CCF_ASSERT(pbft::GlobalState::get_node().is_replica(id), "Not a replica");
  CCF_ASSERT(vc_info()[id].d != Digest(), "Invalid argument");
  CCF_ASSERT(n >= min() && n <= min() + max_out, "Invalid argument");

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

  // check that New_view has 2f + 1 valid View_change digest signatures
  auto proof_count = 0;
  for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
  {
    if (vc_info()[i].d == Digest())
    {
      // we don't have a view change message from this replica
      continue;
    }
    auto sender_principal = pbft::GlobalState::get_node().get_principal(i);
    if (!sender_principal)
    {
      LOG_INFO_FMT("Sender principal has not been configured yet {}", i);
      continue;
    }
    if (sender_principal->verify_signature(
          vc_info()[i].d.digest(),
          vc_info()[i].d.digest_size(),
          vc_info()[i].sig.data(),
          vc_info()[i].sig_size,
          true /* allow self*/))
    {
      proof_count++;
    }
  }
  LOG_TRACE_FMT("new view has verified {} view change messages", proof_count);

  return proof_count >= pbft::GlobalState::get_node().num_correct_replicas();
}
