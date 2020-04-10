// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "message.h"
#include "nodeinfo.h"

//
// New principal messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct New_principal_rep : public Message_rep
{
  NodeId id;
  short port;

  uint32_t ip_len;
  char ip[32];

  uint32_t cert_len;
  unsigned char cert[tls::max_pem_cert_size];

  uint32_t host_name_len;
  char host_name[128];

  bool is_replica;

  char padding[5];
};
#pragma pack(pop)

class New_principal : public Message
{
public:
  New_principal(uint32_t msg_size = 0) : Message(msg_size) {}

  New_principal(
    NodeId id,
    short port,
    std::string ip,
    std::string cert,
    std::string host_name,
    bool is_replica);

  NodeId id() const;
  short port() const;
  std::string ip() const;
  std::string cert() const;
  std::string host_name() const;
  bool is_replica() const;

  bool verify();

private:
  New_principal_rep& rep() const;
};
