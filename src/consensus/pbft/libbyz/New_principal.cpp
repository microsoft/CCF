// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#include "New_principal.h"

#include "Message_tags.h"
#include "Node.h"
#include "Principal.h"
#include "ds/logger.h"
#include "pbft_assert.h"

New_principal::New_principal(
  NodeId id,
  short port,
  std::string ip,
  std::string pubk_sig,
  std::string pubk_enc,
  std::string host_name,
  bool is_replica) :
  Message(New_principal_tag, sizeof(New_principal_rep))
{
  rep().id = id;
  rep().port = port;

  rep().ip_len = ip.size();
  memcpy(rep().ip, ip.data(), ip.size());

  rep().pubk_sig_len = pubk_sig.size();
  memcpy(rep().pubk_sig, pubk_sig.data(), pubk_sig.size());

  rep().pubk_enc_len = pubk_enc.size();
  memcpy(rep().pubk_enc, pubk_enc.data(), pubk_enc.size());

  rep().host_name_len = host_name.size();
  memcpy(rep().host_name, host_name.data(), host_name.size());

  rep().is_replica = is_replica;
}

bool New_principal::verify()
{
  // Check if we are adding a known principal
  std::shared_ptr<Principal> sender = node->get_principal(id());

  return sender == nullptr;
}

bool New_principal::convert(Message* m1, New_principal*& m2)
{
  if (!m1->has_tag(New_principal_tag, sizeof(New_principal_rep)))
  {
    return false;
  }

  m1->trim();
  m2 = (New_principal*)m1;
  return true;
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

std::string New_principal::pubk_sig() const
{
  return std::string(rep().pubk_sig, rep().pubk_sig_len);
}

std::string New_principal::pubk_enc() const
{
  return std::string(rep().pubk_enc, rep().pubk_enc_len);
}

std::string New_principal::host_name() const
{
  return std::string(rep().host_name, rep().host_name_len);
}

bool New_principal::is_replica() const
{
  return rep().is_replica;
}
