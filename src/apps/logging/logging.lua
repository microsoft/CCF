-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {
  __environment = [[
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
        return env.jerr(env.error_codes.BAD_REQUEST, "No such record: " .. args.params.id)
      end
      return env.jsucc({msg = msg})
    end

    function env.record(table)
      if string.len(args.params.msg) == 0 then
        return env.jerr(env.error_codes.BAD_REQUEST, "Cannot record an empty log message")
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
