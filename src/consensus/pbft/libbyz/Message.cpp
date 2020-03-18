// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "Message.h"

#include "Node.h"
#include "pbft_assert.h"

#include <stdlib.h>

#ifdef INSIDE_ENCLAVE
std::unique_ptr<Log_allocator> thread_allocator = nullptr;
#else
thread_local std::unique_ptr<Log_allocator> thread_allocator = nullptr;
#endif
Message::Message(unsigned sz) : msg(0)
{
  if (sz != 0)
  {
    if (thread_allocator == nullptr)
    {
      thread_allocator = std::make_unique<Log_allocator>();
    }
    auto allocator = thread_allocator.get();
    int max_size = (ALIGNED_SIZE(sz));

    auto m = (Message_rep*)allocator->malloc(max_size);
    msg = std::move(std::make_shared<MsgBufCounter>(m, max_size, allocator));
    if (m != nullptr)
    {
      PBFT_ASSERT(ALIGNED(m), "Improperly aligned pointer");
      m->tag = -1;
      m->size = 0;
      m->extra = 0;
    }
  }
  auth_type = Auth_type::unknown;
  auth_len = 0;
  auth_dst_offset = 0;
  next = nullptr;
}

Message::Message(int t, unsigned sz)
{
  if (thread_allocator == nullptr)
  {
    thread_allocator = std::make_unique<Log_allocator>();
  }
  auto allocator = thread_allocator.get();

  int max_size = ALIGNED_SIZE(sz);
  auto m = (Message_rep*)allocator->malloc(max_size);
  msg = std::move(std::make_shared<MsgBufCounter>(m, max_size, allocator));

  PBFT_ASSERT(ALIGNED(m), "Improperly aligned pointer");
  m->tag = t;
  m->size = max_size;
  m->extra = 0;
  auth_type = Auth_type::unknown;
  auth_len = 0;
  auth_dst_offset = 0;
  next = nullptr;
}

Message::Message(Message_rep* cont)
{
  PBFT_ASSERT(ALIGNED(cont), "Improperly aligned pointer");
  int max_size = -1; // To prevent contents from being deallocated or trimmed
  msg = std::move(std::make_shared<MsgBufCounter>(cont, max_size, nullptr));
  auth_type = Auth_type::unknown;
  auth_len = 0;
  auth_dst_offset = 0;
  next = nullptr;
}

Message::~Message() {}

void Message::trim()
{
  if (
    msg->max_size > 0 &&
    msg->allocator->realloc((char*)msg->msg, msg->max_size, msg->msg->size))
  {
    msg->max_size = msg->msg->size;
  }
}

void Message::set_size(int size)
{
  PBFT_ASSERT(msg->msg && ALIGNED(msg->msg), "Invalid state");
  if (!(msg->max_size < 0 || ALIGNED_SIZE(size) <= msg->max_size))
  {
    LOG_INFO << "Error - size:" << size
             << ", aligned_size:" << ALIGNED_SIZE(size)
             << ", max_size:" << msg->max_size << std::endl;
  }
  PBFT_ASSERT(
    msg->max_size < 0 || ALIGNED_SIZE(size) <= msg->max_size, "Invalid state");
  int aligned = ALIGNED_SIZE(size);
  for (int i = size; i < aligned; i++)
  {
    ((char*)msg->msg)[i] = 0;
  }
  msg->msg->size = aligned;
}

bool Message::convert(char* src, unsigned len, int t, int sz, Message& m)
{
  // First check if src is large enough to hold a Message_rep
  if (len < sizeof(Message_rep))
  {
    return false;
  }

  // Check alignment.
  if (!ALIGNED(src))
  {
    return false;
  }

  // Next check tag and message size
  Message ret((Message_rep*)src);
  if (!ret.has_tag(t, sz))
  {
    return false;
  }

  m = ret;
  return true;
}

const char* Message::stag()
{
  static const char* string_tags[] = {"Free_message",
                                      "Request",
                                      "Reply",
                                      "Pre_prepare",
                                      "Prepare",
                                      "Commit",
                                      "Checkpoint",
                                      "Status",
                                      "View_change",
                                      "New_view",
                                      "View_change_ack",
                                      "New_key",
                                      "Meta_data",
                                      "Meta_data_d",
                                      "Data_tag",
                                      "Fetch",
                                      "Query_stable",
                                      "Reply_stable"};
  return string_tags[tag()];
}
