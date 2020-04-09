// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "prepare.h"

#include "message_tags.h"
#include "node.h"
#include "pbft_assert.h"
#include "principal.h"
#include "replica.h"

Prepare::Prepare(
  View v,
  Seqno s,
  Digest& d,
  uint64_t nonce_,
  Principal* dst,
  bool is_signed,
  int id) :
  Message(
    Prepare_tag,
    sizeof(Prepare_rep)
#ifndef USE_PKEY
      + ((dst) ? MAC_size : pbft::GlobalState::get_node().auth_size())),
#else
      + ((dst) ? MAC_size : pbft_max_signature_size)),
#endif
  nonce(nonce_)
{
  rep().extra = (dst) ? 1 : 0;
  rep().view = v;
  rep().seqno = s;
  rep().digest = d;

  if (id < 0)
  {
    rep().id = pbft::GlobalState::get_node().id();
  }

  Digest dh;
  Digest::Context context;
  dh.update_last(context, (char*)&nonce, sizeof(uint64_t));
  dh.finalize(context);
  rep().hashed_nonce = dh;

#ifdef SIGN_BATCH
  rep().digest_sig_size = 0;
  rep().digest_padding.fill(0);
  if (is_signed)
  {
    struct signature
    {
      uint32_t magic = 0xba5eba11;
      NodeId id;
      Digest d;
      Digest n;

      signature(Digest d_, NodeId id_, Digest nonce) : d(d_), id(id_), n(nonce)
      {}
    };

    signature s(d, rep().id, rep().hashed_nonce);

    rep().digest_sig_size = pbft::GlobalState::get_node().gen_signature(
      reinterpret_cast<char*>(&s), sizeof(s), rep().batch_digest_signature);
  }
  else
  {
    rep().batch_digest_signature.fill(0);
  }
#endif

#ifdef USE_PKEY
  rep().prepare_sig_size = 0;
#endif

  rep().padding = 0;
  if (!dst)
  {
#ifndef USE_PKEY
    auth_type = Auth_type::out;
    auth_len = sizeof(Prepare_rep);
    auth_src_offset = 0;
#else
    rep().prepare_sig_size = pbft::GlobalState::get_node().gen_signature(
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
      size() - (int)sizeof(Prepare_rep) < pbft_max_signature_size)
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
