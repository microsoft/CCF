// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "principal.h"

#include "crypt.h"
#include "node.h"
#include "reply.h"

#include <stdlib.h>
#include <strings.h>

Principal::Principal(
  int i, Addr a, bool is_rep, const std::vector<uint8_t>& cert_)
{
  id = i;
  addr = a;
  last_fetch = 0;
  replica = is_rep;

  if (!cert_.empty())
  {
    verifier = std::move(tls::make_unique_verifier(cert_));
    cert = cert_;
  }

  for (int j = 0; j < 4; j++)
  {
    kin[j] = 0;
    kout[j] = 0;
  }

  tstamp = 0;
  my_tstamp = zero_time();
  has_received_network_open_msg = false;
}

bool Principal::verify_signature(
  const char* src,
  unsigned src_len,
  const uint8_t* sig,
  const size_t sig_size,
  bool allow_self)
{
  // Principal never verifies its own authenticator.
  if ((id == pbft::GlobalState::get_node().id()) && !allow_self)
  {
    return false;
  }

  INCR_OP(num_sig_ver);

  bool ret = verifier->verify((uint8_t*)src, src_len, sig, sig_size);

  return ret;
}