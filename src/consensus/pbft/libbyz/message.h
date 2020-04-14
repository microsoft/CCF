// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "message_tags.h"
#include "pbft_assert.h"
#include "types.h"

#include <memory>
#include <mutex>
#include <stddef.h>
#include <stdio.h>

// Maximum message size. Must verify ALIGNED_SIZE.
const int Max_message_size = 32768;

// Minimum required alignment for correctly accessing message fields.
// Must be a power of 2.
#define ALIGNMENT 8

// bool ALIGNED(void *ptr) or bool ALIGNED(long sz)
// Effects: Returns true iff the argument is aligned to ALIGNMENT
#define ALIGNED(ptr) (((uintptr_t)(ptr)) % ALIGNMENT == 0)

// int ALIGNED_SIZE(int sz)
// Effects: Increases sz to the least multiple of ALIGNMENT greater
// than size.
#define ALIGNED_SIZE(sz) \
  ((ALIGNED(sz)) ? (sz) : (sz) - (sz) % ALIGNMENT + ALIGNMENT)

//
// All messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Message_rep
{
  short tag;
  short extra; // May be used to store extra information.
  int size; // Must be a multiple of 8 bytes to ensure proper
            // alignment of embedded messages.

  // Followed by char payload[size-sizeof(Message_rep)];
};
#pragma pack(pop)

enum class Auth_type : int
{
  unknown,
  in,
  out
};

class Message
{
  //
  // Generic messages
  //
protected:
  Message(unsigned sz = 0);
  // Effects: Creates an untagged Message object that can hold up
  // to "sz" bytes and holds zero bytes. Useful to create message
  // buffers to receive messages from the network.

public:
  virtual ~Message();
  // Effects: Deallocates all storage associated with this message.

  void trim();
  // Effects: Deallocates surplus storage.

  char* contents();
  // Effects: Return a byte string with the message contents.

  template <typename T>
  T* contents()
  {
    (T*)msg;
  }

  int size() const;
  // Effects: Fetches the message size.

  int msize() const;
  // Effects: Fetches the maximum number of bytes that can be stored in
  // this message.

  int tag() const;
  // Effects: Fetches the message tag.

  static int get_tag(const uint8_t* data)
  {
    Message_rep* m = (Message_rep*)data;
    return m->tag;
  }

  static int get_size(const uint8_t* data)
  {
    Message_rep* m = (Message_rep*)data;
    return m->size;
  }

  bool has_tag(int t, int sz) const;
  // Effects: If message has tag "t", its size is greater than "sz",
  // its size less than or equal to "max_size", and its size is a
  // multiple of ALIGNMENT, returns true.  Otherwise, returns false.

  View view() const;
  // Effects: Returns any view associated with the message or 0.

  bool full() const;
  // Effects: Messages may be full or empty. Empty messages are just
  // digests of full messages.

  const char* stag();
  // Effects: Returns a string with tag name

protected:
  Message(int t, unsigned sz);
  // Effects: Creates a message with tag "t" that can hold up to "sz"
  // bytes. Useful to create messages to send to the network.

  Message(Message_rep* contents);
  // Requires: "contents" contains a valid Message_rep.
  // Effects: Creates a message from "contents". No copy is made of
  // "contents" and the storage associated with "contents" is not
  // deallocated if the message is later deleted. Useful to create
  // messages from reps contained in other messages.

  void set_size(int size);
  // Effects: Sets message size to the smallest multiple of 8 bytes
  // greater than equal to "size" and pads the message with zeros
  // between "size" and the new message size. Important to ensure
  // proper alignment of embedded messages.

  static bool convert(char* src, unsigned len, int t, int sz, Message& m);
  // Requires: convert can safely read up to "len" bytes starting at
  // "src" Effects: If "src" is a Message_rep for which "has_tag(t,
  // sz)" returns true and sets m to have contents "src". Otherwise,
  // it returns false.  No copy is made of "src" and the storage
  // associated with "contents" is not deallocated if "m" is later
  // deleted.

  friend class Node;
  friend class Pre_prepare;

  Message_rep* msg; // Pointer to the contents of the message.
  Auth_type auth_type;
  int auth_len;
  int auth_dst_offset;
  int auth_src_offset;
  int max_size; // Maximum number of bytes that can be stored in "msg"
                // or "-1" if this instance is not responsible for
                // deallocating the storage in msg.
  // Invariant: max_size <= 0 || 0 < msg->size <= max_size
  bool should_delete = false;

public:
  Message* next;
};

// Methods inlined for speed

inline int Message::size() const
{
  return msg->size;
}

inline int Message::tag() const
{
  return msg->tag;
}

inline bool Message::has_tag(int t, int sz) const
{
  if (max_size >= 0 && msg->size > max_size)
    return false;

  if (!msg || msg->tag != t || msg->size < sz || !ALIGNED(msg->size))
    return false;
  return true;
}

inline View Message::view() const
{
  return 0;
}

inline bool Message::full() const
{
  return true;
}

inline int Message::msize() const
{
  return (max_size >= 0) ? max_size : msg->size;
}

inline char* Message::contents()
{
  return (char*)msg;
}
