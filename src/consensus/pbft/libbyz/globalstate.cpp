// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "globalstate.h"

#include "Client.h"
#include "Node.h"
#include "Replica.h"

// Pointer to global replica object.
std::unique_ptr<Replica> replica;
std::unique_ptr<Client> client;
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
