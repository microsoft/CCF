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
  STATE_ACTIVE = "ACTIVE"

  -- defines which of the members are operators
  function is_operator(member)
    member_info = tables["ccf.members"]:get(member)
    if member_info then
      member_data = member_info.member_data
      if member_data then
        return member_data.is_operator == true
      end
    end
    return false
  end

  -- defines calls that can be passed with sole operator input
  operator_calls = {
    trust_node=true,
    retire_node=true,
    new_node_code=true
  }

  -- count member votes
  operator_votes = 0
  member_votes = 0

  for member, vote in pairs(votes) do
    if vote then
      if is_operator(tonumber(member)) then
        operator_votes = operator_votes + 1
      else
        member_votes = member_votes + 1
      end
    end
  end

  -- count active members, excluding operators
  members_active = 0

  tables["ccf.members"]:foreach(function(member, details)
    if details["status"] == STATE_ACTIVE and not is_operator(member) then
      members_active = members_active + 1
    end
  end)

  -- check for raw_puts to sensitive tables
  SENSITIVE_TABLES = {"ccf.whitelists", "ccf.governance.scripts"}
  for _, call in pairs(calls) do
    if call.func == "raw_puts" then
      for _, sensitive_table in pairs(SENSITIVE_TABLES) do
        if call.args[sensitive_table] then
          -- require unanimity of non-operating members
          if member_votes == members_active then
            return PASSED
          else
            return PENDING
          end
        end
      end
    end
  end

  -- a vote is an operator vote if it's only making operator calls
  operator_vote = true
  for _, call in pairs(calls) do
    if not operator_calls[call.func] then
      operator_vote = false
      break
    end
  end

  -- a majority of members can always pass votes
  if member_votes > math.floor(members_active / 2) then
    return PASSED
  end

  -- a single operator can pass an operator vote
  if operator_vote and operator_votes > 0 then
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
}
