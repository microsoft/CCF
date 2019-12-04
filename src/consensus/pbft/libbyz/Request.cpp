// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Request.h"

#include "Message_tags.h"
#include "Node.h"
#include "Principal.h"
#include "Statistics.h"
#include "pbft_assert.h"

#include <stdlib.h>
#include <strings.h>

#define SIGN_ALL_RW_REQUESTS

// extra & 1 = read only
// extra & 2 = signed

Request::Request(Request_id r, short rr) :
  Message(Request_tag, Max_message_size)
{
  rep().cid = node->id();
  rep().rid = r;
  rep().replier = rr;
  rep().command_size = 0;
  set_size(sizeof(Request_rep));
}

Request* Request::clone() const
{
  Request* ret = (Request*)new Message(max_size);
  memcpy(ret->msg, msg, msg->size);
  return ret;
}

char* Request::store_command(int& max_len)
{
  int max_auth_size =
    std::max(node->principal()->sig_size(), node->auth_size());
  max_len = msize() - sizeof(Request_rep) - max_auth_size;
  return contents() + sizeof(Request_rep);
}

inline void Request::comp_digest(Digest& d)
{
  INCR_OP(num_digests);
  START_CC(digest_cycles);

  d = Digest(
    (char*)&(rep().cid), sizeof(int) + sizeof(Request_id) + rep().command_size);

  STOP_CC(digest_cycles);
}

void Request::authenticate(int act_len, bool read_only)
{
  PBFT_ASSERT(
    (unsigned)act_len <= msize() - sizeof(Request_rep) - node->auth_size(),
    "Invalid request size");

  rep().extra = ((read_only) ? 1 : 0);
  rep().command_size = act_len;
  if (rep().replier == -1)
  {
    rep().replier = rand() % node->num_of_replicas();
  }
  comp_digest(rep().od);

  int old_size = sizeof(Request_rep) + act_len;

#ifndef SIGN_ALL_RW_REQUESTS
  set_size(old_size + node->auth_size());
  auth_type = Auth_type::in;
  auth_len = sizeof(Request_rep);
  auth_dst_offset = old_size;
  auth_src_offset = 0;
#else
  if (!read_only)
  {
    rep().extra |= 2;
    auth_type = Auth_type::unknown;
    set_size(old_size + node->principal()->sig_size());
  }
  else
  {
    set_size(old_size + node->auth_size());
    auth_type = Auth_type::in;
    auth_len = sizeof(Request_rep);
    auth_dst_offset = old_size;
    auth_src_offset = 0;
  }
#endif
}

void Request::re_authenticate(bool change, Principal* p)
{
  if (change)
  {
    rep().extra &= ~1;
  }
  int new_rep = rand() % node->num_of_replicas();
  rep().replier = (new_rep != rep().replier) ?
    new_rep :
    (new_rep + 1) % node->num_of_replicas();

  int old_size = sizeof(Request_rep) + rep().command_size;
  if ((rep().extra & 2) == 0)
  {
    auth_type = Auth_type::in;
    auth_len = sizeof(Request_rep);
    auth_dst_offset = old_size;
    auth_src_offset = 0;
  }
  else
  {
    auth_type = Auth_type::unknown;
  }
}

void Request::sign(int act_len)
{
  PBFT_ASSERT(
    (unsigned)act_len <=
      msize() - sizeof(Request_rep) - node->principal()->sig_size(),
    "Invalid request size");

  rep().extra |= 2;
  rep().command_size = act_len;
  comp_digest(rep().od);

  int old_size = sizeof(Request_rep) + act_len;
  set_size(old_size + node->principal()->sig_size());
}

Request::Request(Request_rep* contents) : Message(contents) {}

bool Request::pre_verify()
{
  const int nid = node->id();
  const int cid = client_id();
  const int old_size = sizeof(Request_rep) + rep().command_size;
  std::shared_ptr<Principal> p = node->get_principal(cid);
  Digest d;

  comp_digest(d);
  if (p != 0 && d == rep().od)
  {
    if ((rep().extra & 2) == 0)
    {
      // Message has an authenticator.
      if (cid != nid && size() - old_size >= node->auth_size(cid))
      {
        return true;
      }
    }
    else
    {
      // Message is signed.
      if (size() - old_size >= p->sig_size())
      {
        return true;
      }
    }
  }
  return false;
}

bool Request::convert(Message* m1, Request*& m2)
{
  if (!m1->has_tag(Request_tag, sizeof(Request_rep)))
  {
    LOG_INFO << "convert request false" << std::endl;
    return false;
  }

  m2 = (Request*)m1;
  m2->trim();
  return true;
}

bool Request::convert(char* m1, unsigned max_len, Request& m2)
{
  if (!Message::convert(m1, max_len, Request_tag, sizeof(Request_rep), m2))
  {
    LOG_INFO << "convert request false" << std::endl;
    return false;
  }

  return true;
}
