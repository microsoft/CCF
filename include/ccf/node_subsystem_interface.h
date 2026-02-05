// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf
{
  class AbstractNodeSubSystem
  {
  public:
    virtual ~AbstractNodeSubSystem() = default;
  };

  template <typename T>
  concept SubsystemType = requires(T) {
    { T::get_subsystem_name() } -> std::convertible_to<std::string_view>;
  } && std::is_base_of_v<AbstractNodeSubSystem, T>;
}
