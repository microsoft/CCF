// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#include "append_entries.h"

#include "ds/logger.h"
#include "message_tags.h"
#include "pbft_assert.h"

Append_entries::Append_entries() :
  Message(Append_entries_tag, sizeof(Append_entries_rep))
{}

Append_entries::Append_entries(uint32_t msg_size) :
  Message(Append_entries_tag, msg_size)
{}

bool Append_entries::verify()
{
  return true;
}

Append_entries_rep& Append_entries::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Append_entries_rep*)msg);
}