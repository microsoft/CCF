// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "Time.h"
#include "keypair.h"
#include "network.h"
#include "types.h"

#include <string.h>
#include <sys/time.h>

extern "C"
{
#include "aes_gcm.h"
}

class Reply;

// Sizes in bytes.
const int UMAC_size = 16;
const int UNonce_size = sizeof(long long);
const int MAC_size = UMAC_size + UNonce_size;

const int Nonce_size = 16;
const int Nonce_size_u = Nonce_size / sizeof(unsigned);
const int Key_size = 16;
const int Key_size_u = Key_size / sizeof(unsigned);

const int Tag_size = 16;
const int Sig_size = 64;
const int Asym_key_size = 32;

class Principal : public IPrincipal
{
public:
  Principal(
    int i,
    Addr a,
    bool replica,
    const uint8_t* pub_key_sig,
    uint8_t* pub_key_enc);
  // Requires: "pkey" points to a null-terminated ascii encoding of
  // an integer in base-16 or is null (in which case no public-key is
  // associated with the principal.)
  // Effects: Creates a new Principal object.

  ~Principal();
  // Effects: Deallocates all the storage associated with principal.

  int pid() const;
  // Effects: Returns the principal identifier.

  const Addr* address() const;
  // Effects: Returns a pointer to the principal's address.

  bool is_replica() const;
  // Effects: Returns true iff this is a replica

  //
  // Cryptography:
  //
  void set_in_key(const unsigned* k);
  // Effects: Sets the session key for incoming messages, in-key, from
  // this principal.

  bool verify_mac_in(const char* src, unsigned src_len, const char* mac);
  // Effects: Returns true iff "mac" is a valid MAC generated by
  // in-key for "src_len" bytes starting at "src".

  void gen_mac_in(const char* src, unsigned src_len, char* dst);
  // Requires: "dst" can hold at least "MAC_size" bytes.
  // Effects: Generates a MAC (with MAC_size bytes) using in-key and
  // places it in "dst".  The MAC authenticates "src_len" bytes
  // starting at "src".

  void set_out_key(unsigned* k, ULong t, bool allow_self = false);
  // Effects: Sets the key for outgoing messages to "k" provided "t"
  // is greater than the last value of "t" in a "set_out_key" call. If
  // "allow_self" is true, it skips the condition on "t".

  bool verify_mac_out(const char* src, unsigned src_len, const char* mac);
  // Effects: Returns true iff "mac" is a valid MAC generated by
  // out-key for "src_len" bytes starting at "src".

  void gen_mac_out(const char* src, unsigned src_len, char* dst);
  // Requires: "dst" can hold at least "MAC_size" bytes.
  // Effects: Generates a MAC (with MAC_size bytes) and
  // out-key and places it in "dst".  The MAC authenticates "src_len"
  // bytes starting at "src".

  ULong last_tstamp() const;
  // Effects: Returns the last timestamp in a new-key message from
  // this principal.

  bool is_stale(Time tv) const;
  // Effects: Returns true iff tv is less than my_tstamp

  const std::array<uint8_t, Asym_key_size>& get_pub_key_enc() const;

  int sig_size() const;
  // Effects: Returns the size of signatures generated by this principal.

  bool verify_signature(
    const char* src,
    unsigned src_len,
    const char* sig,
    bool allow_self = false);
  // Requires: "sig" is at least sig_size() bytes.
  // Effects: Checks a signature "sig" (from this principal) for
  // "src_len" bytes starting at "src". If "allow_self" is false, it
  // always returns false if "this->id == node->id()"; otherwise,
  // returns true if signature is valid.

  unsigned encrypt(
    const char* src,
    unsigned src_len,
    char* dst,
    unsigned dst_len,
    KeyPair* sender_kp);
  // Effects: Encrypts "src_len" bytes starting at "src" using this
  // principal's public-key and places up to "dst_len" of the result in "dst".
  // Returns the number of bytes placed in "dst".

  Request_id last_fetch_rid() const;
  void set_last_fetch_rid(Request_id r);
  // Effects: Gets and sets the last request identifier in a fetch
  // message from this principal.

private:
  int id;
  Addr addr;
  bool replica;
  std::unique_ptr<PublicKey> public_key_sig;
  std::array<uint8_t, Asym_key_size> raw_pub_key_enc;
  int ssize; // signature size
  unsigned
    kin[Key_size_u]; // session key for incoming messages from this principal
  unsigned
    kout[Key_size_u]; // session key for outgoing messages to this principal
  ULong tstamp; // last timestamp in a new-key message from this principal
  Time my_tstamp; // my time when message was accepted

  Request_id
    last_fetch; // Last request_id in a fetch message from this principal

  // UMAC contexts used to generate MACs for incoming and outgoing messages
  aes_gcm_ctx_t ctx_in;
  aes_gcm_ctx_t ctx_out;

  bool verify_mac(
    const char* src,
    unsigned src_len,
    const char* mac,
    const char* unonce,
    aes_gcm_ctx_t ctx);
  // Requires: "ctx" points to a initialized UMAC context
  // Effects: Returns true iff "mac" is a valid MAC generated by
  // key "k" for "src_len" bytes starting at "src".

  void gen_mac(
    const char* src,
    unsigned src_len,
    char* dst,
    const char* unonce,
    aes_gcm_ctx_t ctx);
  // Requires: "dst" can hold at least "MAC_size" bytes and ctx points to a
  // initialized UMAC context.
  // Effects: Generates a UMAC and places it in "dst".  The MAC authenticates
  // "src_len" bytes starting at "src".
#ifdef INSIDE_ENCLAVE
  static long long aes_gcm_nonce;
#else
  static thread_local long long aes_gcm_nonce;
#endif
};

inline const Addr* Principal::address() const
{
  return &addr;
}

inline int Principal::pid() const
{
  return id;
}

inline bool Principal::is_replica() const
{
  return replica;
}

inline ULong Principal::last_tstamp() const
{
  return tstamp;
}

inline bool Principal::is_stale(Time tv) const
{
  return less_than_time(tv, my_tstamp);
}

inline int Principal::sig_size() const
{
  return ssize;
}

inline bool Principal::verify_mac_in(
  const char* src, unsigned src_len, const char* mac)
{
  return verify_mac(src, src_len, mac + UNonce_size, mac, ctx_in);
}

inline void Principal::gen_mac_in(const char* src, unsigned src_len, char* dst)
{
  ++aes_gcm_nonce;
  memcpy(dst, (char*)&aes_gcm_nonce, UNonce_size);
  dst += UNonce_size;
  gen_mac(src, src_len, dst, (char*)&aes_gcm_nonce, ctx_in);
}

inline bool Principal::verify_mac_out(
  const char* src, unsigned src_len, const char* mac)
{
  return verify_mac(src, src_len, mac + UNonce_size, mac, ctx_out);
}

inline const std::array<uint8_t, Asym_key_size>& Principal::get_pub_key_enc()
  const
{
  return raw_pub_key_enc;
}

inline void Principal::gen_mac_out(const char* src, unsigned src_len, char* dst)
{
  ++aes_gcm_nonce;
  memcpy(dst, (char*)&aes_gcm_nonce, UNonce_size);
  dst += UNonce_size;
  gen_mac(src, src_len, dst, (char*)&aes_gcm_nonce, ctx_out);
}

inline Request_id Principal::last_fetch_rid() const
{
  return last_fetch;
}

inline void Principal::set_last_fetch_rid(Request_id r)
{
  last_fetch = r;
}

void random_nonce(unsigned* n);
// Requires: k is an array of at least Nonce_size bytes.
// Effects: Places a new random nonce with size Nonce_size bytes in n.
