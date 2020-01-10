-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {}
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
    "LOG_record_pub"
  ]]
}
