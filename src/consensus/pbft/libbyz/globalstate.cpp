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
    if (client)
    {
      throw std::logic_error(
        "Trying to initialize Replica but Client is already set.");
    }
    replica = std::move(r);
  }

  void GlobalState::set_client(std::unique_ptr<Client> c)
  {
    if (replica)
    {
      throw std::logic_error(
        "Trying to initialize Client but Replica is already set");
    }
    client = std::move(c);
  }

  Replica& GlobalState::get_replica()
  {
    assert(replica != nullptr);
    return *replica.get();
  }

  Client& GlobalState::get_client()
  {
    assert(client != nullptr);
    return *client.get();
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