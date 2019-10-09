// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "ITimer.h"
#include "Message.h"
#include "Message_tags.h"
#include "Principal.h"
#include "Statistics.h"
#include "key_format.h"
#include "network.h"
#include "nodeinfo.h"
#include "pbft_assert.h"
#include "request_id_gen.h"
#include "types.h"

#include <atomic>
#include <stdio.h>
#include <vector>

class Message;
class New_key;
class ITimer;

class Node
{
public:
  Node(const NodeInfo& node_info);
  // Effects: Create a new Node object using the information in
  // node_info.

  virtual ~Node();
  // Effects: Deallocates all storage associated with node.

  View view() const;
  // Effects: Returns the last view known to this node.

  size_t num_of_replicas() const;
  size_t f() const;
  size_t num_correct_replicas() const;

  int id() const;
  // Effects: Returns the principal identifier of the current node.

  std::shared_ptr<Principal> get_principal(int id) const;
  // Effects: Returns the principal that corresponds to
  // identifier "id" or 0 if "id" is not valid.

  std::shared_ptr<Principal> principal() const;
  // Effects: Returns a pointer to the principal identifier associated
  // with the current node.

  void add_principal(const PrincipalInfo& principal_info);
  // Requires: This function can only be called from 1 thread and does not offer
  // the ability to update the principals from multiple threads
  // Effects: adds a new principal (node) to the principals vector

  void configure_principals();
  // Effects: populates the principals array with all the principal info

  bool is_replica(int id) const;
  // Effects: Returns true iff id() is the identifier of a valid replica.

  int primary(View vi) const;
  // Effects: Returns the identifier of the primary for view v.

  inline int primary() const;
  // Effects: Returns  the identifier of the primary for current view.

  //
  // Communication methods:
  //
  void init_network(std::unique_ptr<INetwork>&& network_);

  static const int All_replicas = -1;
  void send(Message* m, int i);
  // Requires: "i" is either All_replicas or a valid principal identifier.
  // Effects: Sends an unreliable message "m" to all replicas or to
  // principal "i".

  void send(Message* m, Principal* p);

  Message* recv();
  // Effects: Blocks waiting to receive a message (while calling
  // handlers on expired timers) then returns message.  The caller is
  // responsible for deallocating the message.

  bool has_messages(long to);
  // Effects: Call handles on expired timers and returns true if
  // there are messages pending. It blocks to usecs waiting for messages

  Request_id new_rid();

  //
  // Cryptography:
  //

  //
  // Authenticator generation and verification:
  //
  int auth_size(int id = -1) const;
  // Effects: Returns the size in bytes of an authenticator for principal
  // "id" (or current principal if "id" is negative.)

  bool verify_mac_in(int i, char* src, unsigned src_len, char* dest = 0) const;
  // Effects: If "i" is an invalid principal identifier or is the
  // identifier of the calling principal, returns false and does
  // nothing. Otherwise, returns true iff: "src"+"src_len" or ("dest"
  // if non-zero) contains a MAC by principal "i" that is
  // valid for the calling principal (i.e. computed with calling
  // principal's in-key.)

  bool verify_mac_out(int i, char* src, unsigned src_len, char* dest = 0) const;
  // Effects: same as verify_mac_in except that checks an authenticator
  // computed with calling principal's out-key.

  void gen_mac(
    int pid, Auth_type atype, char* src, unsigned src_len, char* dest) const;
  // Effects: generates a mac for pid of type atype covering src_len bytes
  // starting at src and place the result in dest.

  //
  // Signature generation:
  //
  unsigned sig_size(int id = -1) const;
  // Requires: id < 0 | id >= num_principals
  // Effects: Returns the size in bytes of a signature for principal
  // "id" (or current principal if "id" is negative.)

  void gen_signature(const char* src, unsigned src_len, char* sig);
  void gen_signature(
    const char* src, unsigned src_len, KeyPair::Signature& sig);
  // Requires: "sig" is at least sig_size() bytes long.
  // Effects: Generates a signature "sig" (from this principal) for
  // "src_len" bytes starting at "src" and puts the result in "sig".

  KeyPair* get_keypair();

  unsigned decrypt(
    const uint8_t* senders_public_key, char* src, char* dst, unsigned dst_len);
  // Effects: decrypts the cyphertext in "src" using this
  // principal's private key and places up to "dst_len" bytes of the
  // result in "dst". Returns the number of bytes placed in "dst".

protected:
  std::string service_name;
  int node_id; // identifier of the current node.
  size_t max_faulty; // Maximum number of faulty replicas.
  size_t num_replicas; // Number of replicas in the service. It must be
                       // num_replicas == 3*max_faulty+1.
  size_t num_clients; // Number of clients in the service

  size_t threshold; // Number of correct replicas. It must be
                    // threshold == 2*max_faulty+1.

  std::unique_ptr<KeyPair> key_pair;

  // Map from principal identifiers to Principal*. The first "num_replicas"
  // principals correspond to the replicas.
  typedef std::unordered_map<int, std::shared_ptr<Principal>> Principal_map;
  std::shared_ptr<Principal_map> atomic_principals =
    std::make_shared<Principal_map>();

  size_t replica_count;
  NodeInfo node_info;
  RequestIdGenerator request_id_generator;

  View v; //  Last view known to this node.
  int cur_primary; // id of primary for the current view.

  //
  // Handling authentication freshness
  //
  ITimer* atimer;
  static void atimer_handler(void* owner);

  virtual void resend_new_key();
  // Effects: resends last_new_key.

  virtual void send_new_key();
  // Effects: Sends a new-key message and updates last_new_key.

  std::shared_ptr<Principal_map> get_principals() const
  {
    return std::atomic_load<Principal_map>(&atomic_principals);
  }

  New_key* last_new_key; // Last new-key message we sent.

  // Communication variables.
  // int sock;
  std::unique_ptr<INetwork> network;

private:
  bool send_only_to_self;

  void send_to_replicas(Message* m);
};

inline View Node::view() const
{
  return v;
}

inline size_t Node::num_of_replicas() const
{
  return num_replicas;
}

inline size_t Node::f() const
{
  return max_faulty;
}

inline size_t Node::num_correct_replicas() const
{
  return threshold;
}

inline int Node::id() const
{
  return node_id;
}

inline std::shared_ptr<Principal> Node::get_principal(int id) const
{
  auto principals = get_principals();
  auto it = principals->find(id);
  if (it == principals->end())
  {
    return nullptr;
  }

  return it->second;
}

inline std::shared_ptr<Principal> Node::principal() const
{
  return get_principal(id());
}

inline bool Node::is_replica(int id) const
{
  auto principal = get_principal(id);
  return principal != nullptr && principal->is_replica();
}

inline int Node::primary(View vi) const
{
  return (vi == v) ? cur_primary : (vi % num_replicas);
}

inline int Node::primary() const
{
  return cur_primary;
}

// TODO: check this is correct
inline int Node::auth_size(int id) const
{
  if (id < 0)
    id = node_id;
  return UMAC_size + UNonce_size;
}

inline bool Node::verify_mac_in(
  int i, char* src, unsigned src_len, char* dest) const
{
  if (!node_info.general_info.should_mac_message)
  {
    return true;
  }

  if (dest == 0)
  {
    dest = src + src_len;
  }

  std::shared_ptr<Principal> p = get_principal(i);
  if (!p)
  {
    return false;
  }

  return p->verify_mac_in(src, src_len, dest);
}

inline bool Node::verify_mac_out(
  int i, char* src, unsigned src_len, char* dest) const
{
  if (!node_info.general_info.should_mac_message)
  {
    return true;
  }

  if (dest == 0)
  {
    dest = src + src_len;
  }

  std::shared_ptr<Principal> p = get_principal(i);
  if (!p)
  {
    return false;
  }

  return p->verify_mac_out(src, src_len, dest);
}

inline void Node::gen_mac(
  int pid, Auth_type atype, char* src, unsigned src_len, char* dst) const
{
  PBFT_ASSERT(dst != nullptr, "Invalid argument");

  auto principals = get_principals();
  auto it = principals->find(pid);
  assert(it != principals->end());

  std::shared_ptr<Principal>& p = it->second;
  if (p == nullptr)
  {
    // principal not ready yet!
    return;
  }

  if (atype == Auth_type::in)
  {
    p->gen_mac_in(src, src_len, dst);
  }
  else if (atype == Auth_type::out)
  {
    p->gen_mac_out(src, src_len, dst);
  }
}

inline unsigned Node::sig_size(int id) const
{
  if (id < 0)
  {
    id = node_id;
  }

  auto principals = get_principals();
  auto it = principals->find(id);
  PBFT_ASSERT(it != principals->end(), "Invalid argument");

  std::shared_ptr<Principal>& p = it->second;
  return p->sig_size();
}

inline KeyPair* Node::get_keypair()
{
  return key_pair.get();
}

inline int cypher_size(char* dst, unsigned dst_len)
{
  // Effects: Returns the size of the cypher in dst or 0 if dst
  // does not contain a valid cypher.
  if (dst_len < Nonce_size + Tag_size)
    return 0;

  return Nonce_size + Tag_size;
}

// Pointer to global node object.
extern Node* node;
