// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "globalstate.h"

// Global replica object.
std::shared_ptr<Replica> replica;
std::shared_ptr<Client> client;

Node* n;

Replica* get_replica()
{
  return replica.get();
}

void set_node(Node* node)
{
  n = node;
}

Node* get_node()
{
  return n;
}