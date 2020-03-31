// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "lua_json.h"
#include "lua_util.h"
#include "node/rpc/frontend.h"
#include "node/rpc/json_handler.h"

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
     * __index metamethod for RequestArgs table.
     * stack: 1 = RequestArgs table, 2 = desired index
     */
    static int index_request_args(lua_State* l)
    {
      auto s = lua_tostring(l, 2);
      return luaL_error(l, "'%s' is not a lua argument", s);
    }

    /**
     * Push a RequestArgs onto the lua stack
     *
     * Leaves a single new value, but may use additional stack space during
     * construction. The pushed value is a table with named keys for the members
     * which should be accessible to lua RPC handlers.
     */
    template <>
    inline void push_raw(lua_State* l, const RequestArgs& args)
    {
      lua_createtable(l, 0, 3);

      push_raw(l, args.caller_id);
      lua_setfield(l, -2, "caller_id");

      push_raw(l, args.rpc_ctx->get_method());
      lua_setfield(l, -2, "method");

      const auto [pack, params] = ccf::details::get_json_params(args.rpc_ctx);
      push_raw(l, params);
      lua_setfield(l, -2, "params");

      // Overwrite __index metamethod for this table
      lua_createtable(l, 0, 1);
      lua_pushcfunction(l, index_request_args);
      lua_setfield(l, -2, "__index");
      lua_setmetatable(l, -2);
    }

    // To get RequestArgs as a return value from lua execution, implement this
    // template <>
    // inline nlohmann::json check_get(lua_State* l, int arg)
    // {}
  } // namespace lua
} // namespace ccf