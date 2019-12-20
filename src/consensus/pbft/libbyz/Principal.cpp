// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Principal.h"

#include "Node.h"
#include "Reply.h"
#include "crypt.h"
#include "epbft_drng.h"

#include <stdlib.h>
#include <strings.h>

Principal::Principal(
  int i, Addr a, bool is_rep, const uint8_t* pub_key_sig, uint8_t* pub_key_enc)
{
  id = i;
  addr = a;
  last_fetch = 0;
  replica = is_rep;

  ssize = Sig_size;
  public_key_sig = std::make_unique<PublicKey>(pub_key_sig);
  std::copy(
    pub_key_enc, pub_key_enc + Asym_key_size, std::begin(raw_pub_key_enc));

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
  const char* src, unsigned src_len, const char* sig, bool allow_self)
{
  // Principal never verifies its own authenticator.
  if ((id == node->id()) && !allow_self)
  {
    return false;
  }

  INCR_OP(num_sig_ver);
  START_CC(sig_ver_cycles);

  bool ret =
    public_key_sig->verify((uint8_t*)src, src_len, (uint8_t*)sig, sig_size());

  STOP_CC(sig_ver_cycles);
  return ret;
}

void random_nonce(unsigned* n)
{
  epbft::IntelDRNG drng;
  drng.rng(0, (unsigned char*)n, Nonce_size);
}
