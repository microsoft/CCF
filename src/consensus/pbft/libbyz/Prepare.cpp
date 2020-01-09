// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Prepare.h"

#include "Message_tags.h"
#include "Node.h"
#include "Principal.h"
#include "Replica.h"
#include "pbft_assert.h"

Prepare::Prepare(View v, Seqno s, Digest& d, Principal* dst, bool is_signed) :
  Message(
    Prepare_tag,
    sizeof(Prepare_rep)
#ifndef USE_PKEY
      + ((dst) ? MAC_size : pbft::GlobalState::get_node().auth_size()))
{
#else
      + ((dst) ? MAC_size : pbft::GlobalState::get_node().sig_size()))
{
#endif
  rep().extra = (dst) ? 1 : 0;
  rep().view = v;
  rep().seqno = s;
  rep().digest = d;
  rep().sig_size = 0;

#ifdef SIGN_BATCH
  if (is_signed)
  {
    rep().sig_size = pbft::GlobalState::get_node().gen_signature(
      d.digest(), d.digest_size(), rep().batch_digest_signature);
  }
  else
  {
    std::fill(
      std::begin(rep().batch_digest_signature),
      std::end(rep().batch_digest_signature),
      0);
  }

#endif

  rep().id = pbft::GlobalState::get_node().id();
  rep().padding = 0;
  if (!dst)
  {
#ifndef USE_PKEY
    auth_type = Auth_type::out;
    auth_len = sizeof(Prepare_rep);
    auth_src_offset = 0;
#else
    rep().sig_size = pbft::GlobalState::get_node().gen_signature(
      contents(), sizeof(Prepare_rep), contents() + sizeof(Prepare_rep));
#endif
  }
  else
  {
    // dst->gen_mac_out(contents(), sizeof(Prepare_rep),
    //     contents()+sizeof(Prepare_rep));

    auth_type = Auth_type::out;
    auth_len = sizeof(Prepare_rep);
    auth_src_offset = 0;
    auth_dst_offset = sizeof(Prepare_rep);
  }
}

void Prepare::re_authenticate(Principal* p)
{
  if (rep().extra == 0)
  {
#ifndef USE_PKEY
    auth_type = Auth_type::out;
    auth_len = sizeof(Prepare_rep);
    auth_src_offset = 0;
#endif
  }
  else
  {
    // p->gen_mac_out(contents(), sizeof(Prepare_rep),
    // contents()+sizeof(Prepare_rep));

    auth_type = Auth_type::out;
  }
  auth_len = sizeof(Prepare_rep);
  auth_src_offset = 0;
  auth_dst_offset = sizeof(Prepare_rep);
}

bool Prepare::pre_verify()
{
  // special case for f == 0
  if (pbft::GlobalState::get_replica().f() == 0)
  {
    return true;
  }

  // This type of message should only be sent by a replica other than me
  // and different from the primary
  if (
    !pbft::GlobalState::get_node().is_replica(id()) ||
    id() == pbft::GlobalState::get_node().id())
  {
    return false;
  }

  if (rep().extra == 0)
  {
    // Check signature size.
#ifndef USE_PKEY
    if (
      view() % pbft::GlobalState::get_replica().num_of_replicas() == id() ||
      size() - (int)sizeof(Prepare_rep) <
        pbft::GlobalState::get_node().auth_size(id()))
    {
      return false;
    }

    return true;
#else
    if (
      view() % pbft::GlobalState::get_replica().num_of_replicas() == id() ||
      size() - (int)sizeof(Prepare_rep) <
        pbft::GlobalState::get_node().sig_size(id()))
    {
      return false;
    }
    return true;
#endif
  }
  else
  {
    if (size() - (int)sizeof(Prepare_rep) < MAC_size)
    {
      return false;
    }

    return true;
  }

  assert(false);
  return false;
}

bool Prepare::convert(Message* m1, Prepare*& m2)
{
  if (!m1->has_tag(Prepare_tag, sizeof(Prepare_rep)))
  {
    return false;
  }

  m2 = (Prepare*)m1;
  m2->trim();
  return true;
}
