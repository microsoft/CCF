// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include "types.h"

#include <cstdint>
#include <memory>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>

class Message;

class IPrincipal
{
public:
  IPrincipal() = default;
  virtual ~IPrincipal() = default;
  virtual const Addr* address() const = 0;
  virtual int pid() const = 0;
  virtual bool is_replica() const = 0;
};

class INetwork
{
public:
  INetwork() = default;
  virtual ~INetwork() = default;
  virtual bool Initialize(in_port_t port) = 0;
  virtual int Send(Message* msg, IPrincipal& to) = 0;
  virtual Message* GetNextMessage() = 0;
  virtual bool has_messages(long to) = 0;
};
