// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "consensus/consensus_types.h"
#include "global_state.h"
#include "itimer.h"
#include "key_format.h"
#include "message.h"
#include "message_tags.h"
#include "network.h"
#include "nodeinfo.h"
#include "pbft_assert.h"
#include "principal.h"
#include "request_id_gen.h"
#include "statistics.h"
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

  virtual ~Node() = default;
  // Effects: Deallocates all storage associated with node.

  View view() const;
  // Effects: Returns the last view known to this node.

  size_t num_of_replicas() const;
  size_t f() const;
  void set_f(ccf::NodeId f);
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
  size_t auth_size(int id = -1) const;
  // Effects: Returns the size in bytes of an authenticator for principal
  // "id" (or current principal if "id" is negative.)

  size_t gen_signature(const char* src, unsigned src_len, char* sig);
  size_t gen_signature(const char* src, unsigned src_len, PbftSignature& sig);
  // Requires: "sig" is at least pbft_max_signature_size bytes long.
  // Effects: Generates a signature "sig" (from this principal) for
  // "src_len" bytes starting at "src" and puts the result in "sig" and
  // returns the length of the signature

protected:
  std::string service_name;
  int node_id; // identifier of the current node.
  size_t max_faulty; // Maximum number of faulty replicas.
  size_t num_replicas; // Number of replicas in the service. It must be
                       // num_replicas == 3*max_faulty+1.
  size_t num_clients; // Number of clients in the service

  size_t threshold; // Number of correct replicas. It must be
                    // threshold == 2*max_faulty+1.

  std::unique_ptr<tls::KeyPair> key_pair;

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

  std::shared_ptr<Principal_map> get_principals() const
  {
    return std::atomic_load<Principal_map>(&atomic_principals);
  }

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

inline size_t Node::auth_size(int id) const
{
  if (id < 0)
    id = node_id;
  return UMAC_size + UNonce_size;
}

inline int cypher_size(char* dst, unsigned dst_len)
{
  // Effects: Returns the size of the cypher in dst or 0 if dst
  // does not contain a valid cypher.
  if (dst_len < Nonce_size + Tag_size)
    return 0;

  return Nonce_size + Tag_size;
}