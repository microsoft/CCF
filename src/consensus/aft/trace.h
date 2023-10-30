// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "impl/state.h"
#include "kv/kv_types.h"

#define RAFT_TRACE_JSON_OUT(json_object) \
  CCF_LOG_OUT(DEBUG, "raft_trace") << json_object

namespace aft
{
  namespace trace
  {
    struct Line
    {
      nlohmann::json j;
      std::shared_ptr<aft::State> state;
      const std::list<kv::Configuration>* configurations = nullptr;

      Line(
        const std::string& function_,
        const std::shared_ptr<aft::State>& state_) :
        state(state_)
      {
        j["function"] = function_;
        j["state"] = *state;
      }

      Line(
        const std::string& function_,
        const std::shared_ptr<aft::State>& state_,
        const std::list<kv::Configuration>& configurations_) :
        state(state_),
        configurations(&configurations_)
      {
        j["function"] = function_;
        j["state"] = *state;
        j["configurations"] = *configurations;
      }

      ~Line()
      {
        j["state_after"] = *state;
        if (configurations != nullptr)
        {
          j["configurations_after"] = *configurations;
        }
        RAFT_TRACE_JSON_OUT(j);
      }
    };
  }
}