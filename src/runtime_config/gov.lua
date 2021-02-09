-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

-- This file defines the default initial contents (ie, Lua scripts) of the governance scripts table.
return {
  pass = [[
  tables, calls, votes, proposer_id = ...

  -- interface definitions
  PASSED = 1
  PENDING = 0
  REJECTED = -1
  STATE_ACTIVE = "ACTIVE"

  -- count member votes
  member_votes = 0

  for member, vote in pairs(votes) do
    if vote then
      member_votes = member_votes + 1
    end
  end

  -- count active members
  members_active = 0

  tables["public:ccf.gov.members.info"]:foreach(function(member, details)
    if details["status"] == STATE_ACTIVE then
      members_active = members_active + 1
    end
  end)

  -- check for raw_puts to sensitive tables
  SENSITIVE_TABLES = {"public:ccf.gov.whitelists", "public:ccf.gov.scripts"}
  for _, call in pairs(calls) do
    if call.func == "raw_puts" then
      for _, sensitive_table in pairs(SENSITIVE_TABLES) do
        if call.args[sensitive_table] then
          -- require unanimity
          if member_votes == members_active then
            return PASSED
          else
            return PENDING
          end
        end
      end
    end
  end

  -- a majority of members can pass votes
  if member_votes > math.floor(members_active / 2) then
    return PASSED
  end

  return PENDING]],

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

  set_service_principal = [[
  tables, args = ...
  table = tables["public:gov.service_principals"]
  table:put(args.id, args.data)
  return true
  ]],

  remove_service_principal = [[
  tables, args = ...
  table = tables["public:gov.service_principals"]
  table:remove(args.id)
  return true
  ]],
}
