// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include <memory>

class Node;
class Replica;

namespace pbft
{
  class GlobalState
  {
  private:
    // Pointer to global replica object.
    static Replica* replica;

  public:
    static void set_replica(std::unique_ptr<Replica> r);
    static Replica& get_replica();
    static Node& get_node();
  };
}