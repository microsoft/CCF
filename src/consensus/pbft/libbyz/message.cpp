// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "message.h"

#include "node.h"
#include "pbft_assert.h"

#include <stdlib.h>

Message::Message(unsigned sz) : msg(0), max_size(ALIGNED_SIZE(sz))
{
  if (sz != 0)
  {
    should_delete = true;

    msg = (Message_rep*)malloc(max_size);
    if (msg != nullptr)
    {
      PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
      msg->tag = -1;
      msg->size = 0;
      msg->extra = 0;
    }
  }
  auth_type = Auth_type::unknown;
  auth_len = 0;
  auth_dst_offset = 0;
  next = nullptr;
}

Message::Message(int t, unsigned sz)
{
  should_delete = true;

  max_size = ALIGNED_SIZE(sz);
  msg = (Message_rep*)malloc(max_size);
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  msg->tag = t;
  msg->size = max_size;
  msg->extra = 0;
  auth_type = Auth_type::unknown;
  auth_len = 0;
  auth_dst_offset = 0;
  next = nullptr;
}

Message::Message(Message_rep* cont)
{
  PBFT_ASSERT(ALIGNED(cont), "Improperly aligned pointer");
  msg = cont;
  max_size = -1; // To prevent contents from being deallocated or trimmed
  auth_type = Auth_type::unknown;
  auth_len = 0;
  auth_dst_offset = 0;
  next = nullptr;
  should_delete = false;
}

Message::~Message()
{
  if (max_size > 0 && msg != nullptr)
  {
    free(msg);
  }
}

void Message::trim()
{
  if (max_size > 0)
  {
    max_size = msg->size;
  }
}

void Message::set_size(int size)
{
  PBFT_ASSERT(msg && ALIGNED(msg), "Invalid state");
  if (!(max_size < 0 || ALIGNED_SIZE(size) <= max_size))
  {
    LOG_INFO << "Error - size:" << size
             << ", aligned_size:" << ALIGNED_SIZE(size)
             << ", max_size:" << max_size << std::endl;
  }
  PBFT_ASSERT(max_size < 0 || ALIGNED_SIZE(size) <= max_size, "Invalid state");
  int aligned = ALIGNED_SIZE(size);
  for (int i = size; i < aligned; i++)
  {
    ((char*)msg)[i] = 0;
  }
  msg->size = aligned;
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
