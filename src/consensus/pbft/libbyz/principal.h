// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "network.h"
#include "time_types.h"
#include "tls/key_pair.h"
#include "types.h"

#include <string.h>
#include <sys/time.h>

class Reply;

// Sizes in bytes.
const size_t UMAC_size = 16;
const size_t UNonce_size = sizeof(long long);
const size_t MAC_size = UMAC_size + UNonce_size;

const int Nonce_size = 16;
const int Nonce_size_u = Nonce_size / sizeof(unsigned);
const int Key_size = 16;
const int Key_size_u = Key_size / sizeof(unsigned);

const int Tag_size = 16;

class Principal : public IPrincipal
{
public:
  Principal(int i, Addr a, bool replica, const std::vector<uint8_t>& cert_);
  // Requires: "cert" points to a node certificate
  // Effects: Creates a new Principal object.

  virtual ~Principal() = default;
  // Effects: Deallocates all the storage associated with principal.

  int pid() const;
  // Effects: Returns the principal identifier.

  const Addr* address() const;
  // Effects: Returns a pointer to the principal's address.

  bool is_replica() const;
  // Effects: Returns true iff this is a replica

  const std::vector<uint8_t>& get_cert() const;

  bool verify_signature(
    const char* src,
    unsigned src_len,
    const uint8_t* sig,
    const size_t sig_size,
    bool allow_self = false);
  // Requires: "sig" is at most pbft_max_signature_size bytes.
  // Effects: Checks a signature "sig" (from this principal) for
  // "src_len" bytes starting at "src". If "allow_self" is false, it
  // always returns false if "this->id == pbft::GlobalState::get_node().id()";
  // otherwise, returns true if signature is valid.

  Request_id last_fetch_rid() const;
  void set_last_fetch_rid(Request_id r);
  // Effects: Gets and sets the last request identifier in a fetch
  // message from this principal.

  bool received_network_open_msg() const;
  void set_received_network_open_msg();
  // Effects: Gets and sets if we have seen a network open message

  void set_certificate(const std::vector<uint8_t>& cert_);
  bool has_certificate_set();

private:
  int id;
  Addr addr;
  bool replica;
  tls::VerifierUniquePtr verifier;
  std::vector<uint8_t> cert;
  unsigned
    kin[Key_size_u]; // session key for incoming messages from this principal
  unsigned
    kout[Key_size_u]; // session key for outgoing messages to this principal
  ULong tstamp; // last timestamp in a new-key message from this principal
  Time my_tstamp; // my time when message was accepted

  Request_id
    last_fetch; // Last request_id in a fetch message from this principal
  bool has_received_network_open_msg;
};

inline bool Principal::has_certificate_set()
{
  return !cert.empty();
}

inline void Principal::set_certificate(const std::vector<uint8_t>& cert_)
{
  verifier = std::move(tls::make_unique_verifier(cert_));
  cert = cert_;
  LOG_TRACE_FMT("Certificate for node {} has been set", id);
}

inline bool Principal::received_network_open_msg() const
{
  return has_received_network_open_msg;
}

inline void Principal::set_received_network_open_msg()
{
  has_received_network_open_msg = true;
}

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

inline const std::vector<uint8_t>& Principal::get_cert() const
{
  return cert;
}

inline Request_id Principal::last_fetch_rid() const
{
  return last_fetch;
}

inline void Principal::set_last_fetch_rid(Request_id r)
{
  last_fetch = r;
}