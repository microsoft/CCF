// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "Message.h"
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

  uint32_t pubk_sig_len;
  char pubk_sig[128];

  uint32_t pubk_enc_len;
  char pubk_enc[128];

  uint32_t host_name_len;
  char host_name[128];

  bool is_replica;

  char padding[5];
};
#pragma pack(pop)

class New_principal : public Message
{
public:
  New_principal(
    NodeId id,
    short port,
    std::string ip,
    std::string pubk_sig,
    std::string pubk_enc,
    std::string host_name,
    bool is_replica);

  NodeId id() const;
  short port() const;
  std::string ip() const;
  std::string pubk_sig() const;
  std::string pubk_enc() const;
  std::string host_name() const;
  bool is_replica() const;

  bool verify();
  bool pre_verify();

  static bool convert(Message* m1, New_principal*& m2);

private:
  New_principal_rep& rep() const;
};
