// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "message.h"

#include "node.h"
#include "pbft_assert.h"

#include <stdlib.h>

Message::Message(unsigned sz)
{
  if (sz != 0)
  {
    int max_size = (ALIGNED_SIZE(sz));
    msg_buf = (Message_rep*)malloc(max_size);
    msg = std::move(make_Ref<MsgBufCounter>(msg_buf, max_size, true));
    if (msg_buf != nullptr)
    {
      PBFT_ASSERT(ALIGNED(msg_buf), "Improperly aligned pointer");
      msg_buf->tag = -1;
      msg_buf->size = 0;
      msg_buf->extra = 0;
    }
  }
  auth_type = Auth_type::unknown;
  auth_len = 0;
  auth_dst_offset = 0;
  next = nullptr;
}

Message::Message(int t, unsigned sz)
{
  int max_size = ALIGNED_SIZE(sz);
  msg_buf = (Message_rep*)malloc(max_size);
  msg = std::move(make_Ref<MsgBufCounter>(msg_buf, max_size, true));

  PBFT_ASSERT(ALIGNED(msg_buf), "Improperly aligned pointer");
  msg_buf->tag = t;
  msg_buf->size = max_size;
  msg_buf->extra = 0;
  auth_type = Auth_type::unknown;
  auth_len = 0;
  auth_dst_offset = 0;
  next = nullptr;
}

Message::Message(Message_rep* cont)
{
  PBFT_ASSERT(ALIGNED(cont), "Improperly aligned pointer");
  int max_size = -1; // To prevent contents from being deallocated or trimmed
  msg = std::move(make_Ref<MsgBufCounter>(cont, max_size, false));
  msg_buf = cont;
  auth_type = Auth_type::unknown;
  auth_len = 0;
  auth_dst_offset = 0;
  next = nullptr;
}

void Message::trim()
{
  if (msg->max_size > 0)
  {
    msg->max_size = msg_buf->size;
  }
}

void Message::set_size(int size)
{
  PBFT_ASSERT(msg_buf && ALIGNED(msg_buf), "Invalid state");
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
    ((char*)msg_buf)[i] = 0;
  }
  msg_buf->size = aligned;
}

bool Message::convert(char* src, unsigned len, int t, int sz, Message& msg_buf)
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

  msg_buf = ret;
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
