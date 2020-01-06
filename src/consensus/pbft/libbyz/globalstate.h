// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include <memory>

class Node;
class Replica;
class Client;

namespace pbft
{
  class GlobalState
  {
  private:
    // Pointer to global replica object.
    static std::unique_ptr<Replica> replica;
    static std::unique_ptr<Client> client;

  public:
    static void set_replica(std::unique_ptr<Replica> r);
    static void set_client(std::unique_ptr<Client> c);
    static Replica& get_replica();
    static Client& get_client();
    static Node& get_node();
  };
}