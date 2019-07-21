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

        TX_NOT_LEADER = -32001,
        TX_FAILED_TO_REPLICATE = -32002,
        SCRIPT_ERROR = -32003,
        INSUFFICIENT_RIGHTS = -32004,
        TX_LEADER_UNKNOWN = -32005,
        RPC_NOT_SIGNED = -32006,
        INVALID_CLIENT_SIGNATURE = -32007,
        INVALID_CALLER_ID = -32008,
        CODE_ID_NOT_FOUND = -32009,
        CODE_ID_RETIRED = -32010,
        RPC_NOT_FORWARDED = -32011,
        QUOTE_NOT_VERIFIED = -32012,

        UNKNOWN_ID = -32050,
        MESSAGE_EMPTY = -32051,
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
        return env.jerr(env.error_codes.UNKNOWN_ID, "No such record: " .. args.params.id) 
      end
      return env.jsucc(msg)
    end
    
    function env.record(table)
      if string.len(args.params.msg) == 0 then
        return env.jerr(env.error_codes.MESSAGE_EMPTY, "Cannot record an empty log message") 
      end
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
