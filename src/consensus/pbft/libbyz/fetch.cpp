// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "fetch.h"

#include "message_tags.h"
#include "node.h"
#include "partition.h"
#include "pbft_assert.h"
#include "principal.h"
#include "replica.h"

Fetch::Fetch(
  Request_id rid, Seqno lu, int level, size_t index, Seqno rc, int repid) :
  Message(
    Fetch_tag, sizeof(Fetch_rep) + pbft::GlobalState::get_node().auth_size())
{
  rep().rid = rid;
  rep().lu = lu;
  rep().level = level;
  rep().index = index;
  rep().rc = rc;
  rep().repid = repid;
  rep().id = pbft::GlobalState::get_node().id();

  auth_type = Auth_type::in;
  auth_len = sizeof(Fetch_rep);
  auth_src_offset = 0;
}

void Fetch::re_authenticate(Principal* p)
{
  auth_type = Auth_type::in;
  auth_len = sizeof(Fetch_rep);
  auth_src_offset = 0;
}

bool Fetch::pre_verify()
{
  if (!pbft::GlobalState::get_node().is_replica(id()))
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

  if (checkpoint() == -1 && replier() != -1)
  {
    return false;
  }

  // Check signature size.
  if (
    size() - (int)sizeof(Fetch_rep) <
    pbft::GlobalState::get_node().auth_size(id()))
  {
    return false;
  }

  return true;
}
