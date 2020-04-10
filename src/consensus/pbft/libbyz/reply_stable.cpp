// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "reply_stable.h"

#include "message_tags.h"
#include "pbft_assert.h"
#include "principal.h"
#include "replica.h"

Reply_stable::Reply_stable(Seqno lc, Seqno lp, int n, Principal* p) :
  Message(Reply_stable_tag, sizeof(Reply_stable_rep) + MAC_size)
{
  rep().lc = lc;
  rep().lp = lp;
  rep().id = pbft::GlobalState::get_node().id();
  rep().nonce = n;

  // p->gen_mac_out(contents(), sizeof(Reply_stable_rep),
  // contents()+sizeof(Reply_stable_rep));

  auth_type = Auth_type::out;
  auth_len = sizeof(Reply_stable_rep);
  auth_src_offset = 0;
  auth_dst_offset = sizeof(Reply_stable_rep);
}

void Reply_stable::re_authenticate(Principal* p)
{
  // p->gen_mac_out(contents(), sizeof(Reply_stable_rep),
  // contents()+sizeof(Reply_stable_rep));

  auth_type = Auth_type::out;
  auth_len = sizeof(Reply_stable_rep);
  auth_src_offset = 0;
  auth_dst_offset = sizeof(Reply_stable_rep);
}

bool Reply_stable::verify()
{
  // Reply_stables must be sent by replicas.
  if (!pbft::GlobalState::get_node().is_replica(id()))
  {
    return false;
  }

  if (rep().lc % checkpoint_interval != 0 || rep().lc > rep().lp)
  {
    return false;
  }

  // Check size.
  if (size() - (int)sizeof(Reply_stable_rep) < MAC_size)
  {
    return false;
  }

  // Check MAC
  std::shared_ptr<Principal> p =
    pbft::GlobalState::get_node().get_principal(id());
  if (p)
  {
    return true;
  }

  return false;
}
