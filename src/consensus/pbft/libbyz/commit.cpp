// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "commit.h"

#include "message_tags.h"
#include "node.h"
#include "pbft_assert.h"
#include "principal.h"
#include "replica.h"

Commit::Commit(View v, Seqno s) :
  Message(
    Commit_tag, sizeof(Commit_rep) + pbft::GlobalState::get_node().auth_size())
{
  rep().view = v;
  rep().seqno = s;
  rep().id = pbft::GlobalState::get_node().id();
  rep().padding = 0;
  auth_type = Auth_type::out;
  auth_len = sizeof(Commit_rep);
  auth_src_offset = 0;
}

Commit::Commit(Commit_rep* contents) : Message(contents) {}

void Commit::re_authenticate(Principal* p)
{
  auth_type = Auth_type::out;
  auth_len = sizeof(Commit_rep);
  auth_src_offset = 0;
}

bool Commit::pre_verify()
{
  // special case for f == 0
  if (pbft::GlobalState::get_replica().f() == 0)
  {
    return true;
  }

  // Commits must be sent by replicas.
  if (
    !pbft::GlobalState::get_node().is_replica(id()) ||
    id() == pbft::GlobalState::get_node().id())
  {
    return false;
  }

  // Check signature size.
  if (
    size() - (int)sizeof(Commit_rep) <
    pbft::GlobalState::get_node().auth_size(id()))
  {
    return false;
  }

  return true;
}

bool Commit::convert(char* m1, unsigned max_len, Commit& m2)
{
  // First check if we can use m1 to create a Commit.
  if (!Message::convert(m1, max_len, Commit_tag, sizeof(Commit_rep), m2))
  {
    return false;
  }
  return true;
}
