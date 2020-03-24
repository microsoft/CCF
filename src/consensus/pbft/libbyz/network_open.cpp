// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#include "Network_open.h"

#include "Message_tags.h"
#include "Node.h"
#include "ds/logger.h"
#include "pbft_assert.h"

Network_open::Network_open(int id) :
  Message(Network_open_tag, sizeof(Network_open_rep))
{
  rep().id = id;
}

bool Network_open::convert(Message* m1, Network_open*& m2)
{
  if (!m1->has_tag(Network_open_tag, sizeof(Network_open_rep)))
  {
    return false;
  }

  m1->trim();
  m2 = (Network_open*)m1;
  return true;
}

int Network_open::id() const
{
  return rep().id;
}

Network_open_rep& Network_open::rep() const
{
  PBFT_ASSERT(ALIGNED(msg), "Improperly aligned pointer");
  return *((Network_open_rep*)msg);
}
