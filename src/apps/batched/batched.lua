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
  ]],

  BATCH_submit = [[
    tables, gov_tables, args = ...
    count = 0
    for n, e in ipairs(args.params) do
      id = e.id
      msg = e.msg
      tables.priv0:put(id, msg)
      count = count + 1
    end
    return env.jsucc(count)
  ]],

  BATCH_fetch = [[
    tables, gov_tables, args = ...
    results = {}
    for n, id in ipairs(args.params) do
      table.insert(results, {id = id, msg = tables.priv0:get(id)})
    end
    return env.jsucc(results)
  ]]
}
