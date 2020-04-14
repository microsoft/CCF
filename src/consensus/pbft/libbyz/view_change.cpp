// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "view_change.h"

#include "message_tags.h"
#include "parameters.h"
#include "pbft_assert.h"
#include "principal.h"
#include "replica.h"

#include <string.h>

View_change::View_change(View v, Seqno ls, int id) :
  Message(View_change_tag, Max_message_size)
{
  rep().view = v;
  rep().last_stable_ckpt = ls;
  rep().id = id;

  // No checkpoints
  rep().n_ckpts = 0;
  for (int i = 0; i < max_out / checkpoint_interval + 1; i++)
  {
    rep().ckpts[i].zero(); // All checkpoint digests are initially null
  }

  // No prepared requests.
  rep().prepared.reset();
  rep().n_reqs = 0;

  rep().digest.zero();

#ifdef SIGN_BATCH
  rep().digest_sig_size = 0;
  rep().digest_signature.fill(0);
  rep().padding.fill(0);
#endif

#ifdef USE_PKEY_VIEW_CHANGES
  rep().vc_sig_size = 0;
#endif
  PBFT_ASSERT(ALIGNED(req_info()), "Improperly aligned pointer");
}

void View_change::add_checkpoint(Seqno n, Digest& d)
{
  int index = (n - last_stable()) / checkpoint_interval;
  rep().ckpts[index] = d;

  if (index >= rep().n_ckpts)
  {
    rep().n_ckpts = index + 1;
  }
}

void View_change::add_request(
  Seqno n, View v, View lv, Digest& d, bool prepared)
{
  PBFT_ASSERT(
    (last_stable() < n) && (n <= last_stable() + max_out), "Invalid argument");
  PBFT_ASSERT(v < view() && lv < view(), "Invalid argument");

  int index = n - last_stable() - 1;
  if (prepared)
  {
    mark(index);
  }

  Req_info& ri = req_info()[index];
  ri.last_sent_view = lv;
  ri.view = v;
  ri.digest = d;

  if (index >= rep().n_reqs)
  {
    // Initialize holes with negative view (i.e. null request)
    for (int i = rep().n_reqs; i < index; i++)
    {
      req_info()[i].view = -1;
      req_info()[i].last_sent_view = -1;
    }
    rep().n_reqs = index + 1;
  }
}

bool View_change::ckpt(Seqno n, Digest& d)
{
  if (last_stable() > n)
  {
    return false;
  }

  int index = (n - last_stable()) / checkpoint_interval;
  if (index >= rep().n_ckpts || rep().ckpts[index].is_zero())
  {
    return false;
  }

  d = rep().ckpts[index];
  return true;
}

bool View_change::proofs(Seqno n, View& v, View& lv, Digest& d, bool& prepared)
{
  int index = n - last_stable() - 1;
  if (index < 0 || index >= rep().n_reqs || req_info()[index].view < 0)
  {
    // Null request.
    return false;
  }

  Req_info& ri = req_info()[index];
  v = ri.view;
  lv = ri.last_sent_view;
  d = ri.digest;
  prepared = test(index);
  return true;
}

View View_change::req(Seqno n, Digest& d)
{
  PBFT_ASSERT(n > last_stable(), "Invalid argument");

  int index = n - last_stable() - 1;
  if (index >= rep().n_reqs || !test(index))
  {
    // Null request.
    d.zero();
    return -1;
  }

  Req_info& ri = req_info()[index];
  d = ri.digest;
  return ri.view;
}

void View_change::re_authenticate(Principal* p)
{
  PBFT_ASSERT(
    rep().n_reqs >= 0 && rep().n_reqs <= max_out && view() > 0,
    "Invalid state");
  PBFT_ASSERT(
    rep().n_ckpts >= 0 && rep().n_ckpts <= max_out / checkpoint_interval + 1,
    "Invalid state");
  PBFT_ASSERT(
    rep().n_ckpts == 0 || rep().ckpts[rep().n_ckpts - 1] != Digest(),
    "Invalid state");
  PBFT_ASSERT(last_stable() >= 0, "Invalid state");

  if (rep().digest.is_zero())
  {
    int old_size = sizeof(View_change_rep) + sizeof(Req_info) * rep().n_reqs;

    // Compute authenticator and update size.
#ifdef USE_PKEY_VIEW_CHANGES
    set_size(old_size + pbft_max_signature_size);
#else
    set_size(old_size + pbft::GlobalState::get_node().auth_size());
#endif

#ifdef SIGN_BATCH
    rep().digest_sig_size = 0;
    rep().digest_signature.fill(0);
#endif

#ifdef USE_PKEY_VIEW_CHANGES
    rep().vc_sig_size = 0;
#endif
    rep().digest = Digest(contents(), old_size);

#ifdef SIGN_BATCH
    rep().digest_sig_size = pbft::GlobalState::get_node().gen_signature(
      rep().digest.digest(),
      rep().digest.digest_size(),
      rep().digest_signature);
#endif

#ifdef USE_PKEY_VIEW_CHANGES
    rep().vc_sig_size = pbft::GlobalState::get_node().gen_signature(
      contents(), old_size, contents() + old_size);
#else
    auth_type = Auth_type::out;
    auth_len = old_size;
    auth_dst_offset = old_size;
    auth_src_offset = 0;
#endif
  }
}

bool View_change::pre_verify()
{
  int nreqs = rep().n_reqs;
  if (
    !pbft::GlobalState::get_node().is_replica(id()) || nreqs < 0 ||
    nreqs > max_out || view() <= 0)
  {
    return false;
  }

  int nckpts = rep().n_ckpts;
  if (nckpts < 0 || nckpts > max_out / checkpoint_interval + 1)
  {
    return false;
  }

  if (nckpts > 0 && rep().ckpts[nckpts - 1].is_zero())
  {
    return false;
  }

  if (last_stable() < 0)
  {
    return false;
  }

  // Check sizes
  int old_size = sizeof(View_change_rep) + sizeof(Req_info) * nreqs;

#ifdef USE_PKEY_VIEW_CHANGES
  if (size() - old_size < pbft_max_signature_size)
  {
    return false;
  }
#else
  if (size() - old_size < pbft::GlobalState::get_node().auth_size(id()))
  {
    return false;
  }
#endif

  // Check consistency of request information.
  for (int i = 0; i < nreqs; i++)
  {
    Req_info& ri = req_info()[i];
    if (ri.last_sent_view >= view() || ri.view >= view())
    {
      return false;
    }
  }

  // Check digest of message.
  if (!verify_digest())
  {
    return false;
  }
  return true;
}

bool View_change::verify_digest()
{
  Digest d = digest(); // save old digest
  digest().zero(); // zero digest

#ifdef SIGN_BATCH
  auto previous_digest_signature = rep().digest_signature;
  auto previous_digest_sig_size = rep().digest_sig_size;
  rep().digest_signature.fill(0);
  rep().digest_sig_size = 0;
#endif

#ifdef USE_PKEY_VIEW_CHANGES
  auto previous_vc_sig_size = rep().vc_sig_size;
  rep().vc_sig_size = 0;
#endif

  bool verified =
    (d ==
     Digest(
       contents(), sizeof(View_change_rep) + sizeof(Req_info) * rep().n_reqs));

  digest() = d; // restore digest
#ifdef SIGN_BATCH
  rep().digest_signature = previous_digest_signature; // restore signature
  rep().digest_sig_size = previous_digest_sig_size; // restore signature size
#endif
#ifdef USE_PKEY_VIEW_CHANGES
  rep().vc_sig_size = previous_vc_sig_size;
#endif
  return verified;
}
