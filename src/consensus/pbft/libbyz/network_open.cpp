// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#include "network_open.h"

#include "ds/ccf_assert.h"
#include "ds/logger.h"
#include "message_tags.h"
#include "node.h"

Network_open::Network_open(int id) :
  Message(Network_open_tag, sizeof(Network_open_rep))
{
  rep().id = id;
}

int Network_open::id() const
{
  return rep().id;
}

Network_open_rep& Network_open::rep() const
{
  CCF_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Network_open_rep*)msg);
}
