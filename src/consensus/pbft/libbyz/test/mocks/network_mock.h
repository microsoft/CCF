// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once
#include "../network_impl.h"
#include "ds/logger.h"
#include "message.h"
#include "node.h"

class MockNetwork : public INetwork
{
public:
  virtual ~MockNetwork() = default;

  virtual bool Initialize(in_port_t port)
  {
    return true;
  }

  virtual int Send(Message* message, IPrincipal& principal)
  {
    return message->size();
  }

  virtual Message* GetNextMessage()
  {
    throw std::logic_error("Should never be called");
  }

  virtual bool has_messages(long to)
  {
    return true;
  }
};

INetwork* Create_Mock_Network();
