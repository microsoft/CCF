// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "globalstate.h"

#include "Client.h"
#include "Node.h"
#include "Replica.h"

namespace pbft
{
  std::unique_ptr<Replica> GlobalState::replica = nullptr;
  std::unique_ptr<Client> GlobalState::client = nullptr;

  void GlobalState::set_replica(std::unique_ptr<Replica> r)
  {
    replica = std::move(r);
  }

  void GlobalState::set_client(std::unique_ptr<Client> c)
  {
    client = std::move(c);
  }

  Replica& GlobalState::get_replica()
  {
    return *replica.get();
  }

  Node& GlobalState::get_node()
  {
    if (replica)
    {
      return *(Node*)replica.get();
    }
    else if (client)
    {
      return *(Node*)client.get();
    }
    throw std::logic_error("Neither Replica nor Client have been initialized.");
  }
}