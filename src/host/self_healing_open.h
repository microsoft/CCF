// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../enclave/interface.h"
#include "ds/ring_buffer_types.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
namespace ccf
{
  class SelfHealingOpenRBHandler
  {
  public:
    ringbuffer::WriterPtr to_enclave;

    SelfHealingOpenRBHandler(
      ringbuffer::AbstractWriterFactory& writer_factory) :
      to_enclave(writer_factory.create_writer_to_inside())
    {}

    void trigger_restart()
    {
      RINGBUFFER_WRITE_MESSAGE(AdminMessage::stop, to_enclave);
    }
  };

  class SelfHealingOpenRBHandlerSingleton
  {
  private:
    static std::unique_ptr<SelfHealingOpenRBHandler>& instance_unsafe()
    {
      static std::unique_ptr<SelfHealingOpenRBHandler> instance = nullptr;
      return instance;
    }

  public:
    static std::unique_ptr<SelfHealingOpenRBHandler>& instance()
    {
      auto& instance = instance_unsafe();
      if (instance == nullptr)
      {
        throw std::logic_error(
          "SelfHealingOpenSingleton instance not initialized");
      }
      return instance;
    }

    static void initialise(ringbuffer::AbstractWriterFactory& writer_factory)
    {
      auto& instance = instance_unsafe();
      if (instance != nullptr)
      {
        throw std::logic_error(
          "SelfHealingOpenSingleton instance already initialized");
      }
      instance = std::make_unique<SelfHealingOpenRBHandler>(writer_factory);
    }
  };
}