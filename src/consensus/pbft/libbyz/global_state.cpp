// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "global_state.h"

#include "node.h"
#include "replica.h"

namespace pbft
{
  Replica* GlobalState::replica = nullptr;

  void GlobalState::set_replica(std::unique_ptr<Replica> r)
  {
    if (replica != nullptr)
    {
      delete replica;
    }
    replica = r.release();
  }

  Replica& GlobalState::get_replica()
  {
    assert(replica != nullptr);
    return *replica;
  }

  Node& GlobalState::get_node()
  {
    assert(replica != nullptr);
    return *(Node*)replica;
  }
}