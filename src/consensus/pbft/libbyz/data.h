// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "message.h"
#include "partition.h"
#include "types.h"

//
// Data messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Data_rep : public Message_rep
{
  size_t index; // index of this page within level
  Seqno lm; // Seqno of last checkpoint in which data was modified
  char data[Block_size];
};
#pragma pack(pop)
static_assert(
  sizeof(Data_rep) + pbft_max_signature_size < Max_message_size,
  "Invalid size");

class Data : public Message
{
  //
  // Data messages
  //
public:
  Data(uint32_t msg_size = 0) : Message(msg_size) {}

  Data(size_t i, Seqno lm, char* data);
  // Effects: Creates a new Data message.  i is the index of he data block, lm
  // is the last sequence number when it was modified, and data is a pointer to
  // the data block.

  size_t index() const;
  // Effects: Returns index of data page

  Seqno last_mod() const;
  // Effects: Returns the seqno of last checkpoint in which data was
  // modified

  char* data() const;
  // Effects: Returns a pointer to the data page.

private:
  Data_rep& rep() const;
  // Effects: Casts contents to a Data_rep&
};

inline Data_rep& Data::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Data_rep*)msg);
}

inline size_t Data::index() const
{
  return rep().index;
}

inline Seqno Data::last_mod() const
{
  return rep().lm;
}

inline char* Data::data() const
{
  return rep().data;
}
