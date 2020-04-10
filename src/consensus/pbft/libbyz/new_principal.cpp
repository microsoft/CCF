// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#include "new_principal.h"

#include "ds/logger.h"
#include "message_tags.h"
#include "node.h"
#include "pbft_assert.h"
#include "principal.h"

New_principal::New_principal(
  NodeId id,
  short port,
  std::string ip,
  std::string cert,
  std::string host_name,
  bool is_replica) :
  Message(New_principal_tag, sizeof(New_principal_rep))
{
  rep().id = id;
  rep().port = port;

  rep().ip_len = ip.size();
  memcpy(rep().ip, ip.data(), ip.size());

  rep().cert_len = cert.size();
  memcpy(rep().cert, cert.data(), cert.size());

  rep().host_name_len = host_name.size();
  memcpy(rep().host_name, host_name.data(), host_name.size());

  rep().is_replica = is_replica;
}

bool New_principal::verify()
{
  // Check if we are adding a known principal
  std::shared_ptr<Principal> sender =
    pbft::GlobalState::get_node().get_principal(id());

  return sender == nullptr;
}

New_principal_rep& New_principal::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((New_principal_rep*)msg);
}

NodeId New_principal::id() const
{
  return rep().id;
}

short New_principal::port() const
{
  return rep().port;
}

std::string New_principal::ip() const
{
  return std::string(rep().ip, rep().ip_len);
}

std::string New_principal::cert() const
{
  return std::string(rep().cert, rep().cert + rep().cert_len);
}

std::string New_principal::host_name() const
{
  return std::string(rep().host_name, rep().host_name_len);
}

bool New_principal::is_replica() const
{
  return rep().is_replica;
}
