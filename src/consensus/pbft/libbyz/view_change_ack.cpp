// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "view_change_ack.h"

#include "ds/logger.h"
#include "message_tags.h"
#include "node.h"
#include "pbft_assert.h"
#include "principal.h"

View_change_ack::View_change_ack(View v, int id, int vcid, Digest const& vcd) :
  Message(View_change_ack_tag, sizeof(View_change_ack_rep) + MAC_size)
{
  rep().v = v;
  rep().id = pbft::GlobalState::get_node().id();
  rep().vcid = vcid;
  rep().vcd = vcd;

  int old_size = sizeof(View_change_ack_rep);
  set_size(old_size + MAC_size);

  auth_type = Auth_type::out;
  auth_len = old_size;
  auth_src_offset = 0;
  auth_dst_offset = old_size;
}

void View_change_ack::re_authenticate(Principal* p)
{
  // p->gen_mac_out(contents(), sizeof(View_change_ack_rep),
  // contents()+sizeof(View_change_ack_rep));

  auth_type = Auth_type::out;
  auth_len = sizeof(View_change_ack_rep);
  auth_src_offset = 0;
  auth_dst_offset = sizeof(View_change_ack_rep);
}

bool View_change_ack::verify()
{
  // These messages must be sent by replicas other than me, the replica that
  // sent the corresponding view-change, or the primary.
  if (
    !pbft::GlobalState::get_node().is_replica(id()) ||
    id() == pbft::GlobalState::get_node().id() || id() == vc_id() ||
    pbft::GlobalState::get_node().primary(view()) == id())
  {
    return false;
  }

  if (view() <= 0 || !pbft::GlobalState::get_node().is_replica(vc_id()))
  {
    return false;
  }

  // Check sizes
  if (size() - (int)sizeof(View_change_ack) < MAC_size)
  {
    return false;
  }

  // Check MAC.
  std::shared_ptr<Principal> p =
    pbft::GlobalState::get_node().get_principal(id());
  if (!p)
  {
    return false;
  }

  return true;
}
