// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "message.h"
#include "nodeinfo.h"

//
// Append entries messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Append_entries_rep : public Message_rep
{};
#pragma pack(pop)

class Append_entries : public Message
{
public:
  Append_entries();
  Append_entries(uint32_t msg_size);

  bool verify();

private:
  Append_entries_rep& rep() const;
};
