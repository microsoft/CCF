// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "pre_prepare.h"

#include "message_tags.h"
#include "pbft_assert.h"
#include "prepare.h"
#include "prepared_cert.h"
#include "principal.h"
#include "replica.h"
#include "req_queue.h"
#include "request.h"

Pre_prepare::Pre_prepare(
  View v,
  Seqno s,
  Req_queue& reqs,
  size_t& requests_in_batch,
  uint64_t nonce_,
  Prepared_cert* prepared_cert) :
  Message(
    Pre_prepare_tag,
    sizeof(Pre_prepare_rep) +
      sizeof(Digest) * Max_requests_in_batch + // Message header + max number of
                                               // messages in a pre_prepare
      pbft_max_signature_size +
      pbft::GlobalState::get_node().auth_size() + // Merkle root signature
      (pbft_max_signature_size + sizeof(uint64_t)) *
        pbft::GlobalState::get_node()
          .num_of_replicas()), // signatures for the previous pre_prepare
  nonce(nonce_)
{
  rep().view = v;
  rep().seqno = s;
  rep().replicated_state_merkle_root.fill(0);
  rep().contains_gov_req = false;
  rep().last_gov_req_updated = 0;

  Digest dh;
  Digest::Context context;
  dh.update_last(context, (char*)&nonce_, sizeof(uint64_t));
  dh.finalize(context);
  rep().hashed_nonce = dh;

  INCR_OP(pp_digest);

  // Fill in the request portion with as many requests as possible
  // and compute digest.
  requests_in_batch = 0;
  Digest big_req_ds[Max_requests_in_batch];
  int n_big_reqs = 0;
  char* next_req = requests();
#ifndef USE_PKEY
  char* max_req =
    next_req + msize() - pbft::GlobalState::get_node().auth_size();
#else
  char* max_req = next_req + msize() -
    pbft::GlobalState::get_replica().max_nd_bytes() - pbft_max_signature_size;
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
        pbft::GlobalState::get_replica().big_reqs()->add_pre_prepare(
          reqs.remove(), s, v);
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

  INCR_CNT(sum_batch_size, requests_in_batch);
  INCR_OP(batch_size_histogram[requests_in_batch]);

  LOG_TRACE << "request in batch:" << requests_in_batch << std::endl;

  if (prepared_cert == nullptr)
  {
    rep().num_prev_pp_sig = 0;
  }
  else
  {
    const auto& proof = prepared_cert->get_pre_prepared_cert_proof();
    rep().num_prev_pp_sig = proof.size();

    uint8_t* sigs = (uint8_t*)contents() + sizeof(Pre_prepare_rep) +
      rep().rset_size + rep().n_big_reqs * sizeof(Digest);

    for (const auto& p : proof)
    {
      Included_sig* ic = reinterpret_cast<Included_sig*>(sigs);
      ic->pid = p.first;
      std::copy(
        p.second.signature.begin(), p.second.signature.end(), ic->sig.begin());
      std::fill(
        ic->sig.end(),
        ic->sig.end() + ALIGNED_SIZE(pbft_max_signature_size) -
          pbft_max_signature_size,
        0);
      sigs += ALIGNED_SIZE(sizeof(Included_sig));
    }
  }

  // Compute authenticator and update size.
  int old_size = sizeof(Pre_prepare_rep) + rep().rset_size +
    rep().n_big_reqs * sizeof(Digest) +
    rep().num_prev_pp_sig * ALIGNED_SIZE(sizeof(Included_sig));

#ifndef USE_PKEY
  set_size(old_size + pbft::GlobalState::get_node().auth_size());
  auth_type = Auth_type::out;
  auth_len = sizeof(Pre_prepare_rep);
  auth_dst_offset = old_size;
  auth_src_offset = 0;
#else
  set_size(old_size + pbft_max_signature_size);
#endif

#ifdef SIGN_BATCH
  rep().sig_size = 0;
  rep().batch_digest_signature.fill(0);
  rep().padding.fill(0);
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
  auth_src_offset = 0;
#endif
}

int Pre_prepare::id() const
{
  return pbft::GlobalState::get_replica().primary(view());
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
  pbft::GlobalState::get_replica().set_next_expected_sig_offset();
  rep().sig_size = pbft::GlobalState::get_node().gen_signature(
    d.digest(), d.digest_size(), rep().batch_digest_signature);
#endif

  return true;
}

bool Pre_prepare::calculate_digest(Digest& d)
{
  // Check sizes
#ifndef USE_PKEY
  int min_size = sizeof(Pre_prepare_rep) + rep().rset_size +
    rep().n_big_reqs * sizeof(Digest) +
    pbft::GlobalState::get_node().auth_size(
      pbft::GlobalState::get_replica().primary(view()));
#else
  int min_size = sizeof(Pre_prepare_rep) + rep().rset_size +
    rep().n_big_reqs * sizeof(Digest) + pbft_max_signature_size;
#endif
  if (size() >= min_size)
  {
    INCR_OP(pp_digest);

    // Check digest.
    Digest::Context context;

    d.update_last(context, (char*)&(rep().view), sizeof(View));
    d.update_last(context, (char*)&(rep().seqno), sizeof(Seqno));
    d.update_last(
      context,
      (const char*)rep().replicated_state_merkle_root.data(),
      rep().replicated_state_merkle_root.size());
    d.update_last(context, (char*)&rep().contains_gov_req, sizeof(uint64_t));
    d.update_last(context, (char*)&rep().last_gov_req_updated, sizeof(Seqno));
    d.update_last(context, (char*)&rep().hashed_nonce, sizeof(uint64_t));
    d.update_last(context, (char*)&rep().ctx, sizeof(rep().ctx));
    d.update_last(context, (char*)&rep().rset_size, sizeof(rep().rset_size));
    d.update_last(context, (char*)&rep().n_big_reqs, sizeof(rep().n_big_reqs));

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

#ifdef SIGN_BATCH
    d.update_last(
      context, (char*)&rep().num_prev_pp_sig, sizeof(rep().num_prev_pp_sig));
#endif

    // Finalize digest of requests and non-det-choices.
    d.update_last(
      context, (char*)big_reqs(), rep().n_big_reqs * sizeof(Digest));
    d.finalize(context);

    return true;
  }
  return false;
}

bool Pre_prepare::pre_verify()
{
  int sender = view() % pbft::GlobalState::get_replica().num_of_replicas();

  if (rep().n_big_reqs > Max_requests_in_batch)
  {
    return false;
  }

  if (check_digest())
  {
#ifdef SIGN_BATCH
    if (is_signed())
    {
      auto sender_principal =
        pbft::GlobalState::get_node().get_principal(sender);
      if (!sender_principal)
      {
        LOG_INFO_FMT("Sender principal has not been configured yet {}", sender);
        return false;
      }

      if (
        !sender_principal->has_certificate_set() &&
        pbft::GlobalState::get_node().f() == 0)
      {
        // Do not verify signature of first pre-prepare since node certificate
        // required for verification is contained in the pre-prepare requests
        return true;
      }

      if (!sender_principal->verify_signature(
            rep().digest.digest(),
            rep().digest.digest_size(),
            get_digest_sig().data(),
            rep().sig_size))
      {
        LOG_INFO << "failed to verify signature on the digest, seqno:"
                 << rep().seqno << std::endl;
        return false;
      }
    }
#endif

    int sz = rep().rset_size + rep().n_big_reqs * sizeof(Digest);
#ifndef USE_PKEY
    return true;
#else
    if (d == rep().digest)
    {
      Principal* ps = pbft::GlobalState::get_node().get_principal(sender);
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
    Request* r = pbft::GlobalState::get_replica().big_reqs()->lookup(
      msg->big_req_digest(big_req));
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

bool Pre_prepare::Requests_iter::has_more_requests()
{
  if (next_req < msg->requests() + msg->rep().rset_size)
  {
    return true;
  }

  if (big_req < msg->num_big_reqs())
  {
    return true;
  }

  return false;
}

Pre_prepare::ValidProofs_iter::ValidProofs_iter(Pre_prepare* m)
{
  msg = m;
  proofs = m->proofs();
  proofs_left = m->proofs_size();
}

bool Pre_prepare::ValidProofs_iter::get(int& id, bool& is_valid_proof)
{
  if (proofs_left <= 0)
  {
    return false;
  }

  auto* ic = reinterpret_cast<Included_sig*>(proofs);
  id = ic->pid;
  is_valid_proof = true;
  proofs += ALIGNED_SIZE(sizeof(Included_sig));
  proofs_left--;

  return true;
}

void Pre_prepare::set_merkle_roots_and_ctx(
  const std::array<uint8_t, MERKLE_ROOT_SIZE>& replicated_state_merkle_root,
  int64_t ctx)
{
  std::copy(
    std::begin(replicated_state_merkle_root),
    std::end(replicated_state_merkle_root),
    std::begin(rep().replicated_state_merkle_root));
  rep().ctx = ctx;
}

void Pre_prepare::set_last_gov_request(
  Seqno last_seqno_with_gov_req, bool did_exec_gov_req)
{
  rep().contains_gov_req = did_exec_gov_req;
  rep().last_gov_req_updated = last_seqno_with_gov_req;
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