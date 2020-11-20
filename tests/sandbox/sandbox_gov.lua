-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

-- This file defines the default initial contents (ie, Lua scripts) of the governance scripts table.
return {
  pass = [[
  tables, calls, votes = ...

  -- interface definitions
  PASSED = 1
  PENDING = 0
  REJECTED = -1

  -- The constitution in a real CCF application deployment would at least
  -- count votes and compare to a threshold of members, but in the sandbox sample,
  -- all votes pass automatically.

  return PASSED]],

  environment_proposal = [[
  __Puts = {}
  function __Puts:new(o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end

  function __Puts:put(t, key, value)
    self[t] = self[t] or {}
    table.insert(self[t], {k = key, v = value})
    return self
  end
  -- create a frontend for __Puts that hides function entries
  Puts = setmetatable({}, {__index = __Puts})

  __Calls = {}
  function __Calls:new(o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end

  function __Calls:call(_func, _args)
    table.insert(self, {func=_func, args=_args})
    return self
  end
  Calls = setmetatable({}, {__index = __Calls})

  function empty_list()
    return setmetatable({}, {__was_object=false})
  end

  function empty_object()
    return setmetatable({}, {__was_object=true})
  end
  ]],

  -- scripts that can be proposed to be called

  raw_puts = [[
  tables, puts = ...
  for table_name, entries in pairs(puts) do
    t = tables[table_name]
    for _,entry in pairs(entries) do
      t:put(entry.k, entry.v)
    end
  end
  return true]],

}
