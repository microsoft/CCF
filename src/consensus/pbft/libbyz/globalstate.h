// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include <memory>
class Node;
class Replica;
class Client;

// Pointer to global replica object.
extern std::shared_ptr<Replica> replica;
extern std::shared_ptr<Client> client;

extern Replica* get_replica();
extern void set_node(Node* node);
extern Node* get_node();