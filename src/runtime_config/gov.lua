-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

-- This file defines the default initial contents (ie, Lua scripts) of the gov_scipts table.
return {
  quorum = [[
  tables, calls = ...
  -- count active members
  n_active = 0
  STATE_ACTIVE = 1
  tables["members"]:foreach(function(k, v) 
    if v["status"] == STATE_ACTIVE then 
      n_active = n_active + 1 
    end 
  end)
  -- check for raw_puts to sensitive tables
  SENSITIVE_TABLES = {"whitelists", "scripts"}
  for _,call in pairs(calls) do
    if call.func == "raw_puts" then
      for _,sensitive_table in pairs(SENSITIVE_TABLES) do
        if call.args[sensitive_table] then
          -- require unanimity
          return n_active 
        end
      end
    end
  end

  return math.floor(n_active / 2 + 1)]],
  
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
  Calls =  setmetatable({}, {__index = __Calls})
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

  new_user = [[
  tables, cert = ...
  if tables.usercerts:get(cert) then return end
  NEXT_USER_ID = 1
  user_id = tables.values:get(NEXT_USER_ID)
  tables.values:put(NEXT_USER_ID, user_id + 1)
  tables.usercerts:put(cert, user_id)
  ]]
}
