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
  class SelfHealingOpen
  {
  public:
    ringbuffer::WriterPtr to_enclave;

    SelfHealingOpen(ringbuffer::AbstractWriterFactory& writer_factory) :
      to_enclave(writer_factory.create_writer_to_inside())
    {}

    void trigger_restart()
    {
      RINGBUFFER_WRITE_MESSAGE(AdminMessage::stop, to_enclave);
    }
  };

  class SelfHealingOpenSingleton
  {
  private:
    static std::unique_ptr<SelfHealingOpen>& instance_unsafe()
    {
      static std::unique_ptr<SelfHealingOpen> instance = nullptr;
      return instance;
    }

  public:
    static std::unique_ptr<SelfHealingOpen>& instance()
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
      instance = std::make_unique<SelfHealingOpen>(writer_factory);
    }
  };
}