// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Node.h"

#include "ITimer.h"
#include "Message.h"
#include "Message_tags.h"
#include "New_key.h"
#include "Principal.h"
#include "Time.h"
#include "crypt.h"
#include "ds/logger.h"
#include "parameters.h"
#include "pbft_assert.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef NDEBUG
#  define NDEBUG
#endif

// Pointer to global node instance.
Node* node = 0;

// Enable statistics
#include "Statistics.h"

Node::Node(const NodeInfo& node_info_) : node_info(node_info_)
{
  node = this;

  // Compute clock frequency.
  init_clock_mhz();

  replica_count = 0;

  uint8_t privk[Asym_key_size];
  format::from_hex(node_info.privk, privk, Asym_key_size);
  key_pair = std::make_unique<KeyPair>(privk);

  service_name = node_info.general_info.service_name;

  // read max_faulty and compute derived variables
  max_faulty = node_info.general_info.max_faulty;
  num_replicas = node_info.general_info.num_replicas;
  if (num_replicas <= 2 * max_faulty)
  {
    LOG_FATAL << "Not enough replicas: " << num_replicas
              << " for desired f: " << max_faulty << std::endl;
    throw std::logic_error(
      "Not enough replicas: " + std::to_string(num_replicas) +
      " for desired f: " + std::to_string(max_faulty));
  }
  num_clients = node_info.general_info.num_clients;
  if (num_replicas > Max_num_replicas)
  {
    PBFT_FAIL("Invalid number of replicas");
  }
  if (max_faulty == 0)
  {
    // f == 0 so num_correct_replicas is set to 1
    // Certificates containing only the replica's
    // own certificate are considered complete
    threshold = 1;
  }
  else
  {
    threshold = num_replicas - max_faulty;
  }

  LOG_INFO << " max faulty (f): " << max_faulty
           << " num replicas: " << num_replicas << std::endl;

  // Read authentication timeout
  int at = node_info.general_info.auth_timeout;

  node_id = -1;
  node_id = node_info.own_info.id;

  add_principal(node_info.own_info);

  if (node_id < 0)
  {
    PBFT_FAIL("Could not find my principal");
  }

  LOG_INFO << "My id is " << node_id << std::endl;

  // Initialize current view number and primary.
  v = 0;
  cur_primary = 0;

#ifndef INSIDE_ENCLAVE
  // Sleep for more than a second to ensure strictly increasing
  // timestamps.
  sleep(2);
#endif

  last_new_key = 0;
  atimer = new ITimer(at, atimer_handler, this);

  send_only_to_self = ((f() == 0 && is_replica(id())));
}

Node::~Node()
{
  delete atimer;
  delete last_new_key;
}

void Node::add_principal(const PrincipalInfo& principal_info)
{
  LOG_INFO << "Adding principal with id:" << principal_info.id << std::endl;
  auto principals = get_principals();
  auto it = principals->find(principal_info.id);
  if (it != principals->end())
  {
    LOG_INFO << "Principal with id: " << principal_info.id
             << " has already been configured" << std::endl;
    return;
  }
  Addr a;
  bzero((char*)&a, sizeof(a));
  a.sin_family = AF_INET;
  uint8_t pks[Asym_key_size];
  uint8_t pke[Asym_key_size];

  format::from_hex(principal_info.pubk_sig, pks, Asym_key_size);
  format::from_hex(principal_info.pubk_enc, pke, Asym_key_size);
#ifndef INSIDE_ENCLAVE
  a.sin_addr.s_addr = inet_addr(principal_info.ip.c_str());
  a.sin_port = htons(principal_info.port);
#endif
  auto new_principals = std::make_shared<Principal_map>(*principals);

  new_principals->insert(
    {principal_info.id,
     std::make_shared<Principal>(
       principal_info.id, a, principal_info.is_replica, pks, pke)});

  std::atomic_store(&atomic_principals, new_principals);

  LOG_INFO << "Added principal with id:" << principal_info.id << std::endl;

  if (principal_info.is_replica)
  {
    replica_count++;
  }
  if (principal_info.id != node_id)
  {
    node->send_new_key();
  }
}

void Node::configure_principals()
{
  for (auto& pi : node_info.general_info.principal_info)
  {
    if (pi.id != node_id)
    {
      LOG_INFO << "Adding principal: " << pi.id << std::endl;
      add_principal(pi);
    }
  }
}

// TODO: add to node.h and where ever node is being created
void Node::init_network(std::unique_ptr<INetwork>&& network_)
{
  auto principals = get_principals();
  LOG_INFO << "principals - count:" << principals->size() << std::endl;
  network = std::move(network_);
  auto it = principals->find(node_id);
  assert(it != principals->end());
  network->Initialize(it->second->address()->sin_port);
}

void Node::send(Message* m, int i)
{
  if (i == All_replicas)
  {
    send_to_replicas(m);
    return;
  }

  std::shared_ptr<Principal> p = get_principal(i);
  if (p == nullptr)
  {
    // principal not ready yet!
    return;
  }

  send(m, p.get());
}

void Node::send(Message* m, Principal* p)
{
  PBFT_ASSERT(m->size() <= Max_message_size, "Message is too big");
  PBFT_ASSERT(m->tag() < Max_message_tag, "Invalid message tag");
  PBFT_ASSERT(p != nullptr, "Must send to a principal");

  INCR_OP(message_counts_out[m->tag()]);

  int error = 0;
  int size = m->size();
  while (error < size)
  {
    INCR_OP(num_sendto);
    INCR_CNT(bytes_out, size);
    START_CC(sendto_cycles);
    if (!network)
    {
      throw std::logic_error("Network not set");
    }

    error = network->Send(m, *p);

    STOP_CC(sendto_cycles);
#ifndef NDEBUG
    if (error < 0 && error != EAGAIN)
      perror("Node::send: sendto");
#endif
  }
}

bool Node::has_messages(long to)
{
  if (!network)
  {
    throw std::logic_error("Network not set");
  }
  return network->has_messages(to);
}

Message* Node::recv()
{
  if (!network)
  {
    throw std::logic_error("Network not set");
  }
  Message* m = network->GetNextMessage();

  LOG_TRACE << "received message tag:" << m->tag() << std::endl;

  INCR_OP(message_counts_in[m->tag()]);
  INCR_CNT(bytes_in, m->size());

  return m;
}

void Node::gen_signature(const char* src, unsigned src_len, char* sig)
{
  INCR_OP(num_sig_gen);
  START_CC(sig_gen_cycles);

  auto signature = key_pair->sign((uint8_t*)src, src_len);

  memcpy(sig, &signature[0], signature.size());

  STOP_CC(sig_gen_cycles);
}

void Node::gen_signature(
  const char* src, unsigned src_len, KeyPair::Signature& sig)
{
  INCR_OP(num_sig_gen);
  START_CC(sig_gen_cycles);

  key_pair->sign((uint8_t*)src, src_len, sig);

  STOP_CC(sig_gen_cycles);
}

unsigned Node::decrypt(
  const uint8_t* senders_public_key, char* src, char* dst, unsigned dst_len)
{
  // decrypted message expected to be
  // as big as encrypted message
  // tag follows the encrypted message

  // read tag that comes after the encrypted message
  uint8_t tag[Tag_size];
  memcpy(tag, src + dst_len, Tag_size);

  // will memcpy into dst the decrypted message
  bool ok = key_pair->decrypt(
    senders_public_key, (const uint8_t*)src, dst_len, (uint8_t*)dst, tag);

  if (ok)
  {
    // how much to advance
    return dst_len + Tag_size;
  }

  return 0;
}

Request_id Node::new_rid()
{
  return request_id_generator.next_rid();
}

void Node::atimer_handler(void* owner)
{
  // Multicast new key to all replicas.
  ((Node*)owner)->send_new_key();
}

void Node::send_new_key()
{
  delete last_new_key;

  // Multicast new key to all replicas.
  last_new_key = new New_key();
  send(last_new_key, All_replicas);

  // Stop timer if not expired and then restart it
  atimer->stop();
  atimer->restart();
}

void Node::resend_new_key()
{
  if (last_new_key != nullptr)
  {
    send(last_new_key, All_replicas);
  }
  else
  {
    send_new_key();
  }
}

void Node::send_to_replicas(Message* m)
{
  LOG_TRACE << "replica_count:" << replica_count
            << ", num_replicas:" << num_replicas << " m:" << m->tag()
            << std::endl;

  if (send_only_to_self && m->tag() != Status_tag)
  {
    LOG_TRACE << "Only sending to self" << std::endl;
    send(m, node_id);
  }
  else
  {
    auto principals = get_principals();
    for (auto& it : *principals)
    {
      if (it.second->is_replica() && it.second->pid() != node_id)
      {
        send(m, it.second.get());
      }
    }
  }
}

void Node::set_f(ccf::NodeId f)
{
  LOG_INFO << "***** setting f to " << f << "*****" << std::endl;
  max_faulty = f;
  send_only_to_self = (f == 0);
}
