// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Query_stable.h"

#include "Message_tags.h"
#include "Principal.h"
#include "Replica.h"
#include "pbft_assert.h"

Query_stable::Query_stable() :
  Message(
    Query_stable_tag,
    sizeof(Query_stable_rep) + pbft::GlobalState::get_node().auth_size())
{
  rep().id = pbft::GlobalState::get_node().id();
  // TODO(#PBFT): Get a better random function for nonce
  rep().nonce = (uint64_t)this;
  auth_type = Auth_type::out;
  auth_len = sizeof(Query_stable_rep);
  auth_src_offset = 0;
}

void Query_stable::re_authenticate(Principal* p)
{
  auth_type = Auth_type::out;
  auth_len = sizeof(Query_stable_rep);
  auth_src_offset = 0;
}

bool Query_stable::verify()
{
  // Query_stables must be sent by replicas.
  if (!pbft::GlobalState::get_node().is_replica(id()))
  {
    return false;
  }

  // Check signature size.
  if (
    size() - (int)sizeof(Query_stable_rep) <
    pbft::GlobalState::get_node().auth_size(id()))
  {
    return false;
  }

  return true;
}

bool Query_stable::convert(Message* m1, Query_stable*& m2)
{
  if (!m1->has_tag(Query_stable_tag, sizeof(Query_stable_rep)))
  {
    return false;
  }
  m1->trim();
  m2 = (Query_stable*)m1;
  return true;
}
