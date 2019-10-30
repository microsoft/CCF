// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Commit.h"

#include "Message_tags.h"
#include "Node.h"
#include "Principal.h"
#include "Replica.h"
#include "pbft_assert.h"

Commit::Commit(View v, Seqno s) :
  Message(Commit_tag, sizeof(Commit_rep) + node->auth_size())
{
  rep().view = v;
  rep().seqno = s;
  rep().id = node->id();
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

bool Commit::verify()
{
  return true;
}

bool Commit::pre_verify()
{
  // special case for f == 0
  if (replica->f() == 0)
  {
    return true;
  }

  // Commits must be sent by replicas.
  if (!node->is_replica(id()) || id() == node->id())
  {
    return false;
  }

  // Check signature size.
  if (size() - (int)sizeof(Commit_rep) < node->auth_size(id()))
  {
    return false;
  }

  verified_auth = node->verify_mac_in(id(), contents(), sizeof(Commit_rep));
  return true;
}

bool Commit::convert(Message* m1, Commit*& m2)
{
  if (!m1->has_tag(Commit_tag, sizeof(Commit_rep)))
  {
    return false;
  }

  m2 = (Commit*)m1;
  m2->trim();
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
