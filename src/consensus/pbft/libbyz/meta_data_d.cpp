// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "meta_data_d.h"

#include "message_tags.h"
#include "node.h"
#include "partition.h"
#include "pbft_assert.h"
#include "principal.h"
#include "replica.h"

Meta_data_d::Meta_data_d(Request_id r, int l, size_t i, Seqno ls) :
  Message(Meta_data_d_tag, sizeof(Meta_data_d_rep))
{
  PBFT_ASSERT(l < PLevels, "Invalid argument");
  PBFT_ASSERT(i < PLevelSize[l], "Invalid argument");
  rep().rid = r;
  rep().ls = ls;
  rep().l = l;
  rep().i = i;
  rep().id = pbft::GlobalState::get_replica().id();

  for (int k = 0; k < max_out / checkpoint_interval + 1; k++)
  {
    rep().digests[k].zero();
  }
  rep().n_digests = 0;
}

void Meta_data_d::add_digest(Seqno n, Digest& digest)
{
  PBFT_ASSERT(
    (last_stable() <= n) && (n <= last_stable() + max_out), "Invalid argument");

  int index = (n - last_stable()) / checkpoint_interval;
  rep().digests[index] = digest;

  if (index >= rep().n_digests)
  {
    rep().n_digests = index + 1;
  }
}

bool Meta_data_d::digest(Seqno n, Digest& d)
{
  if (last_stable() > n)
  {
    return false;
  }

  int index = (n - last_stable()) / checkpoint_interval;
  if (index >= rep().n_digests || rep().digests[index].is_zero())
  {
    return false;
  }

  d = rep().digests[index];
  return true;
}

void Meta_data_d::authenticate(Principal* p)
{
  set_size(sizeof(Meta_data_d_rep));

  auth_type = Auth_type::out;
  auth_len = sizeof(Meta_data_d_rep);
  auth_src_offset = 0;
  auth_dst_offset = sizeof(Meta_data_d_rep);
}

bool Meta_data_d::verify()
{
  // Meta-data must be sent by replicas.
  if (
    !pbft::GlobalState::get_node().is_replica(id()) ||
    pbft::GlobalState::get_node().id() == id() || last_stable() < 0)
  {
    return false;
  }

  if (level() < 0 || level() >= PLevels)
  {
    return false;
  }

  if (index() < 0 || index() >= PLevelSize[level()])
  {
    return false;
  }

  if (
    rep().n_digests < 1 || rep().n_digests >= max_out / checkpoint_interval + 1)
  {
    return false;
  }

  // Check principal exists
  std::shared_ptr<Principal> p =
    pbft::GlobalState::get_node().get_principal(id());
  if (p)
  {
    return true;
  }

  return false;
}
