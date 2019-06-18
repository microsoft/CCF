// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "luautil.h"
#include "node/rpc/frontend.h"

/**
 * @file luarpcargs.h
 * @brief Convert from RpcFrontend::RequestArgs to a lua table, giving named
 * access to RPC args and explicit errors on attempts to access missing keys.
 */
namespace ccf
{
  namespace lua
  {
    /**
     * Push a RequestArgs onto the lua stack
     *
     * Leaves a single new value, but may use additional stack space during
     * construction. The pushed value is a table with named keys for the members
     * which should be accessible to lua RPC handlers.
     */
    template <>
    inline void push_raw(lua_State* l, const RpcFrontend::RequestArgs& args)
    {}

    // To get RequestArgs as a return value from lua execution, implement this
    // template <>
    // inline nlohmann::json check_get(lua_State* l, int arg)
    // {}
  } // namespace lua
} // namespace ccf