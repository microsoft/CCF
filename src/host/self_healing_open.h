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
  struct SelfHealingOpenJoinInfo
  {
    std::string url;
    std::string service_identity;
  };

  class SelfHealingOpen
  {
  public:
    ringbuffer::WriterPtr to_enclave;
    std::optional<SelfHealingOpenJoinInfo> join_info;

    SelfHealingOpen(ringbuffer::AbstractWriterFactory& writer_factory) :
      to_enclave(writer_factory.create_writer_to_inside()),
      join_info(std::nullopt)
    {}

    void trigger_restart_and_join_url(
      const std::string& url, const std::string& service_identity)
    {
      join_info = SelfHealingOpenJoinInfo{
        .url = url, .service_identity = service_identity};
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