// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "meta_data.h"

#include "message_tags.h"
#include "node.h"
#include "partition.h"
#include "pbft_assert.h"
#include "principal.h"
#include "replica.h"

Meta_data::Meta_data(
  Request_id r, int l, size_t i, Seqno lu, Seqno lm, Digest& d) :
  Message(Meta_data_tag, Max_message_size)
{
  PBFT_ASSERT(l < PLevels, "Invalid argument");
  PBFT_ASSERT(i < PLevelSize[l], "Invalid argument");
  rep().rid = r;
  rep().lu = lu;
  rep().lm = lm;
  rep().l = l;
  rep().i = i;
  rep().id = pbft::GlobalState::get_replica().id();
  rep().d = d;
  rep().np = 0;
  set_size(sizeof(Meta_data_rep));
}

void Meta_data::add_sub_part(size_t i, Digest& d)
{
  Part_info& p = parts()[rep().np];
  p.i = i;
  p.d = d;
  rep().np++;
  set_size(sizeof(Meta_data_rep) + rep().np * sizeof(Part_info));
}

Meta_data::Sub_parts_iter::Sub_parts_iter(Meta_data* m)
{
  msg = m;
  cur_mod = 0;
  max_mod = m->rep().np;
  if (m->level() != PLevels - 1)
  {
    index = m->index() * PSize[m->level() + 1];
    max_index = index + PSize[m->level() + 1];
  }
  else
  {
    index = m->index();
    max_index = index + 1;
  }
}

bool Meta_data::Sub_parts_iter::get(size_t& i, Digest& d)
{
  if (index < max_index)
  {
    if (cur_mod < max_mod)
    {
      Part_info* cur = msg->parts() + cur_mod;
      if (index < cur->i)
      {
        d.zero();
        i = index;
        index++;
        return true;
      }

      PBFT_ASSERT(index == cur->i, "Invalid state");
      d = cur->d;
      i = index;
      index++;
      cur_mod++;
      return true;
    }

    d.zero();
    i = index;
    index++;
    return true;
  }
  return false;
}

bool Meta_data::verify()
{
  // Meta-data must be sent by replicas.
  if (
    !pbft::GlobalState::get_node().is_replica(id()) ||
    pbft::GlobalState::get_node().id() == id())
  {
    return false;
  }

  // Meta_data messages are not sent for leaf partitions
  if (level() < 0 || level() >= PLevels - 1)
  {
    return false;
  }

  if (index() < 0 || index() >= PLevelSize[level()])
  {
    return false;
  }

  if (rep().np > 1 && rep().np > PSize[level() + 1])
  {
    return false;
  }

  if (last_mod() > last_uptodate())
  {
    return false;
  }

  // Check sizes
  int old_size = sizeof(Meta_data_rep) + rep().np * sizeof(Part_info);
  if (size() < ALIGNED_SIZE(old_size))
  {
    return false;
  }

  Part_info* ps = parts();
  int min = index() * PSize[level() + 1];
  int max = min + PSize[level() + 1];
  std::vector<bool> sparts(max - min, false);
  for (int i = 0; i < rep().np; i++)
  {
    int si = ps[i].i;
    if (si < min || si >= max || sparts[si - min])
    {
      return false;
    }
    sparts[si - min] = true;
  }

  return true;
}
