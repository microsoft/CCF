// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "query_stable.h"

#include "message_tags.h"
#include "pbft_assert.h"
#include "principal.h"
#include "replica.h"

Query_stable::Query_stable() :
  Message(
    Query_stable_tag,
    sizeof(Query_stable_rep) + pbft::GlobalState::get_node().auth_size())
{
  rep().id = pbft::GlobalState::get_node().id();
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
