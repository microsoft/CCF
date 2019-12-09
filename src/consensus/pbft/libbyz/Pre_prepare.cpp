// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Pre_prepare.h"

#include "Message_tags.h"
#include "Prepare.h"
#include "Principal.h"
#include "Replica.h"
#include "Req_queue.h"
#include "Request.h"
#include "pbft_assert.h"

Pre_prepare::Pre_prepare(
  View v, Seqno s, Req_queue& reqs, size_t& requests_in_batch) :
  Message(Pre_prepare_tag, Max_message_size)
{
  rep().view = v;
  rep().seqno = s;
  rep().full_state_merkle_root.fill(0);
  rep().replicated_state_merkle_root.fill(0);

  START_CC(pp_digest_cycles);
  INCR_OP(pp_digest);

  // Fill in the request portion with as many requests as possible
  // and compute digest.
  requests_in_batch = 0;
  Digest big_req_ds[Max_requests_in_batch];
  int n_big_reqs = 0;
  char* next_req = requests();
#ifndef USE_PKEY
  char* max_req =
    next_req + msize() - replica->max_nd_bytes() - node->auth_size();
#else
  char* max_req =
    next_req + msize() - replica->max_nd_bytes() - node->sig_size();
#endif

  for (Request* req = reqs.first(); req != 0; req = reqs.first())
  {
    if (req->size() <= Request::big_req_thresh)
    {
      // Small requests are inlined in the pre-prepare message.
      if (
        next_req + req->size() <= max_req &&
        requests_in_batch < Max_requests_in_batch)
      {
#pragma GCC diagnostic push
        memcpy(next_req, req->contents(), req->size());
#pragma GCC diagnostic pop
        // TODO: this is wasteful because we are padding for every digest
        next_req += req->size();
        requests_in_batch++;
        PBFT_ASSERT(ALIGNED(next_req), "Improperly aligned pointer");
        delete reqs.remove();
      }
      else
      {
        break;
      }
    }
    else
    {
      // Big requests are sent offline and their digests are sent
      // with pre-prepare message.
      if (
        n_big_reqs < Max_requests_in_batch &&
        next_req + sizeof(Digest) <= max_req)
      {
        big_req_ds[n_big_reqs++] = req->digest();

        // Add request to replica's big reqs table.
        replica->big_reqs()->add_pre_prepare(reqs.remove(), s, v);
        max_req -= sizeof(Digest);
        requests_in_batch++;
      }
      else
      {
        break;
      }
    }
  }
  rep().rset_size = next_req - requests();
  PBFT_ASSERT(rep().rset_size >= 0, "Request too big");

  // Put big requests after regular ones.
  for (int i = 0; i < n_big_reqs; i++)
  {
    *(big_reqs() + i) = big_req_ds[i];
  }
  rep().n_big_reqs = n_big_reqs;

  if (rep().rset_size > 0 || n_big_reqs > 0)
  {
    // Fill in the non-deterministic choices portion.
    int non_det_size = replica->max_nd_bytes();
    replica->compute_non_det(s, non_det_choices(), &non_det_size);
    PBFT_ASSERT(ALIGNED(non_det_size), "Invalid non-deterministic choice");
    rep().non_det_size = non_det_size;
  }
  else
  {
    // Null request
    rep().non_det_size = 0;
  }

  STOP_CC(pp_digest_cycles);
  INCR_CNT(sum_batch_size, requests_in_batch);
  INCR_OP(batch_size_histogram[requests_in_batch]);

  LOG_TRACE << "request in batch:" << requests_in_batch << std::endl;

  // Compute authenticator and update size.
  int old_size = sizeof(Pre_prepare_rep) + rep().rset_size +
    rep().n_big_reqs * sizeof(Digest) + rep().non_det_size;

#ifndef USE_PKEY
  set_size(old_size + node->auth_size());
  auth_type = Auth_type::out;
  auth_len = sizeof(Pre_prepare_rep);
  auth_dst_offset = old_size;
  auth_src_offset = 0;
#else
  set_size(old_size + node->sig_size());
#endif

#ifdef SIGN_BATCH
  std::fill(
    std::begin(rep().batch_digest_signature),
    std::end(rep().batch_digest_signature),
    0);
#endif

  trim();
}

Pre_prepare* Pre_prepare::clone(View v) const
{
  Pre_prepare* ret = (Pre_prepare*)new Message(max_size);
  memcpy(ret->msg, msg, msg->size);
  ret->rep().view = v;
  return ret;
}

void Pre_prepare::re_authenticate(Principal* p)
{
#ifndef USE_PKEY
  auth_type = Auth_type::out;
  auth_len = sizeof(Pre_prepare_rep);
  auth_dst_offset = (non_det_choices() + rep().non_det_size) - contents();
  auth_src_offset = 0;
#endif
}

int Pre_prepare::id() const
{
  return replica->primary(view());
}

bool Pre_prepare::check_digest()
{
  Digest d;
  if (!calculate_digest(d))
  {
    return false;
  }

  return d == rep().digest;
}

bool Pre_prepare::is_signed()
{
#ifdef SIGN_BATCH
  return (
    std::none_of(
      std::begin(rep().batch_digest_signature),
      std::end(rep().batch_digest_signature),
      [](int i) { return i != 0; }) == false);
#endif
  return true;
}

bool Pre_prepare::set_digest(int64_t signed_version)
{
  rep().ctx = std::max(rep().ctx, signed_version);

  Digest d;
  if (!calculate_digest(d))
  {
    return false;
  }

  rep().digest = d;

#ifdef SIGN_BATCH
  if (
    replica->should_sign_next_and_reset() ||
    (rep().seqno == replica->next_expected_sig_offset()) || node->f() == 0)
  {
    replica->set_next_expected_sig_offset();
    node->gen_signature(
      d.digest(), d.digest_size(), rep().batch_digest_signature);
  }
#endif

  return true;
}

bool Pre_prepare::calculate_digest(Digest& d)
{
  // Check sizes
#ifndef USE_PKEY
  int min_size = sizeof(Pre_prepare_rep) + rep().rset_size +
    rep().n_big_reqs * sizeof(Digest) + rep().non_det_size +
    node->auth_size(replica->primary(view()));
#else
  int min_size = sizeof(Pre_prepare_rep) + rep().rset_size +
    rep().n_big_reqs * sizeof(Digest) + rep().non_det_size +
    node->sig_size(replica->primary(view()));
#endif
  if (size() >= min_size)
  {
    START_CC(pp_digest_cycles);
    INCR_OP(pp_digest);

    // Check digest.
    Digest::Context context;

    d.update_last(context, (char*)&(rep().view), sizeof(View));
    d.update_last(context, (char*)&(rep().seqno), sizeof(Seqno));
    d.update_last(
      context,
      (const char*)rep().full_state_merkle_root.data(),
      rep().full_state_merkle_root.size());
    d.update_last(
      context,
      (const char*)rep().replicated_state_merkle_root.data(),
      rep().replicated_state_merkle_root.size());
    d.update_last(context, (char*)&rep().ctx, sizeof(rep().ctx));

    Request req;
    char* max_req = requests() + rep().rset_size;
    for (char* next = requests(); next < max_req; next += req.size())
    {
      if (Request::convert(next, max_req - next, req))
      {
        d.update_last(context, (char*)&(req.digest()), sizeof(Digest));
      }
      else
      {
        STOP_CC(pp_digest_cycles);
        return false;
      }
    }

    // Finalize digest of requests and non-det-choices.
    d.update_last(
      context,
      (char*)big_reqs(),
      rep().n_big_reqs * sizeof(Digest) + rep().non_det_size);
    d.finalize(context);

    STOP_CC(pp_digest_cycles);
    return true;
  }
  return false;
}

bool Pre_prepare::pre_verify()
{
  int sender = view() % replica->num_of_replicas();

  if (rep().n_big_reqs > Max_requests_in_batch)
  {
    return false;
  }

  if (check_digest())
  {
#ifdef SIGN_BATCH
    if (is_signed())
    {
      if (!node->get_principal(sender)->verify_signature(
            rep().digest.digest(),
            rep().digest.digest_size(),
            (const char*)get_digest_sig().data()))
      {
        LOG_INFO << "failed to verify signature on the digest, seqno:"
                 << rep().seqno << std::endl;
        return false;
      }
    }
#endif

    int sz =
      rep().rset_size + rep().n_big_reqs * sizeof(Digest) + rep().non_det_size;
#ifndef USE_PKEY
    return true;
#else
    if (d == rep().digest)
    {
      Principal* ps = node->get_principal(sender);
      if (!ps)
      {
        return false;
      }
      return true;
    }
#endif
  }
  return false;
}

bool Pre_prepare::verify(int mode)
{
  if (mode != NRC)
  {
    // Check inline requests authentication
    Request req;
    char* max_req = requests() + rep().rset_size;
    for (char* next = requests(); next < max_req; next += req.size())
    {
      Request::convert(next, max_req - next, req);

      // TODO: If we batch requests from different clients inline. We need to
      // change this a bit. Otherwise, a good client could be denied
      // service just because its request was batched with the request
      // of another client.  A way to do this would be to include a
      // bitmap with a bit set for each request that verified.
    }
  }

  return true;
}

Pre_prepare::Requests_iter::Requests_iter(Pre_prepare* m)
{
  msg = m;
  next_req = m->requests();
  big_req = 0;
}

bool Pre_prepare::Requests_iter::get(Request& req)
{
  if (next_req < msg->requests() + msg->rep().rset_size)
  {
    req = Request((Request_rep*)next_req);
    next_req += req.size();
    return true;
  }

  return get_big_request(req);
}

bool Pre_prepare::Requests_iter::get_big_request(Request& req)
{
  bool is_request_present;
  bool result = get_big_request(req, is_request_present);
  PBFT_ASSERT(is_request_present, "Missing big req");
  return result;
}

bool Pre_prepare::Requests_iter::get_big_request(
  Request& req, bool& is_request_present)
{
  is_request_present = true;
  if (big_req < msg->num_big_reqs())
  {
    Request* r = replica->big_reqs()->lookup(msg->big_req_digest(big_req));
    big_req++;
    if (r == 0)
    {
      is_request_present = false;
      return true;
    }
    PBFT_ASSERT(r != 0, "Missing big req");
    req = Request((Request_rep*)r->contents());
    return true;
  }

  return false;
}

bool Pre_prepare::convert(Message* m1, Pre_prepare*& m2)
{
  if (!m1->has_tag(Pre_prepare_tag, sizeof(Pre_prepare_rep)))
  {
    return false;
  }

  m2 = (Pre_prepare*)m1;
  m2->trim();
  return true;
}

void Pre_prepare::set_merkle_roots_and_ctx(
  const std::array<uint8_t, MERKLE_ROOT_SIZE>& full_state_merkle_root,
  const std::array<uint8_t, MERKLE_ROOT_SIZE>& replicated_state_merkle_root,
  int64_t ctx)
{
  std::copy(
    std::begin(full_state_merkle_root),
    std::end(full_state_merkle_root),
    std::begin(rep().full_state_merkle_root));
  std::copy(
    std::begin(replicated_state_merkle_root),
    std::end(replicated_state_merkle_root),
    std::begin(rep().replicated_state_merkle_root));
  rep().ctx = ctx;
}

const std::array<uint8_t, MERKLE_ROOT_SIZE>& Pre_prepare::
  get_full_state_merkle_root() const
{
  return rep().full_state_merkle_root;
}

const std::array<uint8_t, MERKLE_ROOT_SIZE>& Pre_prepare::
  get_replicated_state_merkle_root() const
{
  return rep().replicated_state_merkle_root;
}

int64_t Pre_prepare::get_ctx() const
{
  return rep().ctx;
}