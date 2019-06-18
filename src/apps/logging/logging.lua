-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {
  __environment = [[
    env = {
      error_codes = {
        PARSE_ERROR = -32700,
        INVALID_REQUEST = -32600,
        METHOD_NOT_FOUND = -32601,
        INVALID_PARAMS = -32602,
        INTERNAL_ERROR = -32603,
        INVALID_CLIENT_SIGNATURE = -32605,
        INVALID_CALLER_ID = -32606,
        
        INSUFFICIENT_RIGHTS = -32006,
        DENIED = -32007
      }
    }

    function env.jsucc(result)
      return {result = result}
    end

    function env.jerr(code, message)
      return {error = {code = code, message = message}}
    end

    -- custom functions for logging
    function env.get(table)
      msg = table:get(args.params.id)
      if not msg then
        return env.jerr(env.error_codes.INVALID_PARAMS, "No such record") 
      end
      return env.jsucc(msg)
    end
    
    function env.record(table)
      table:put(args.params.id, args.params.msg)
      return env.jsucc(true)
    end
  ]],

  LOG_get = [[
    -- SNIPPET_START: lua_params
    tables, gov_tables, args = ...
    -- SNIPPET_END: lua_params
    return env.get(tables.priv0)
  ]],

  LOG_get_pub = [[
    tables, gov_tables, args = ...
    return env.get(tables.pub0)
  ]],

  LOG_record = [[
    tables, gov_tables, args = ...
    return env.record(tables.priv0)
  ]],

  LOG_record_pub = [[
    tables, gov_tables, args = ...
    return env.record(tables.pub0)
  ]]
}
