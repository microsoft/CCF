// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Checkpoint.h"

#include "Message_tags.h"
#include "Principal.h"
#include "Replica.h"
#include "parameters.h"
#include "pbft_assert.h"

Checkpoint::Checkpoint(Seqno s, Digest& d, bool stable) :
#ifndef USE_PKEY_CHECKPOINTS
  Message(Checkpoint_tag, sizeof(Checkpoint_rep) + node->auth_size())
{
#else
  Message(Checkpoint_tag, sizeof(Checkpoint_rep) + node->sig_size())
{
#endif
  rep().extra = (stable) ? 1 : 0;
  rep().seqno = s;
  rep().digest = d;
  rep().id = node->id();
  rep().padding = 0;

#ifndef USE_PKEY_CHECKPOINTS
  auth_type = Auth_type::out;
  auth_len = sizeof(Checkpoint_rep);
  auth_src_offset = 0;
#else
  node->gen_signature(
    contents(), sizeof(Checkpoint_rep), contents() + sizeof(Checkpoint_rep));
#endif
}

void Checkpoint::re_authenticate(Principal* p, bool stable)
{
#ifndef USE_PKEY_CHECKPOINTS
  if (stable)
    rep().extra = 1;
  auth_type = Auth_type::out;
  auth_len = sizeof(Checkpoint_rep);
  auth_src_offset = 0;
#else
  if (rep().extra != 1 && stable)
  {
    rep().extra = 1;
    node->gen_signature(
      contents(), sizeof(Checkpoint_rep), contents() + sizeof(Checkpoint_rep));
  }
#endif
}

bool Checkpoint::verify()
{
  return verified_auth;
}

bool Checkpoint::pre_verify()
{
  // Checkpoints must be sent by replicas.
  if (!node->is_replica(id()))
  {
    return false;
  }

  // Check signature size.
#ifndef USE_PKEY_CHECKPOINTS
  if (size() - (int)sizeof(Checkpoint_rep) < node->auth_size(id()))
  {
    return false;
  }

  verified_auth = node->verify_mac_in(id(), contents(), sizeof(Checkpoint_rep));
#else
  if (size() - (int)sizeof(Checkpoint_rep) < node->sig_size(id()))
  {
    return false;
  }

  std::shared_ptr<Principal> p = node->get_principal(id());
  if (p != nullptr)
  {
    verified_auth = p->verify_signature(
      contents(), sizeof(Checkpoint_rep), contents() + sizeof(Checkpoint_rep));
  }
#endif

  return true;
}

bool Checkpoint::convert(Message* m1, Checkpoint*& m2)
{
  if (!m1->has_tag(Checkpoint_tag, sizeof(Checkpoint_rep)))
  {
    return false;
  }
  m1->trim();
  m2 = (Checkpoint*)m1;
  return true;
}
