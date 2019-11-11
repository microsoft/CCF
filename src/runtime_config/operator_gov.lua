-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

-- This file defines the default initial contents (ie, Lua scripts) of the gov_scipts table.
return {
  pass = [[
  tables, calls, votes = ...

  -- defines which of the members are operators
  function is_operator(member)
    return member == "0"
  end

  -- defines calls that can be passed with sole operator input
  operator_calls = {
    trust_node=true,
    retire_node=true,
    new_code=true
  }

  operator_votes = 0
  member_votes = 0

  for member, vote in pairs(votes) do
    if vote then
      if is_operator(member) then
        operator_votes = operator_votes + 1
      else
        member_votes = member_votes + 1
      end
    end
  end

  -- count active members, excluding operators
  members_active = 0
  STATE_ACTIVE = 1

  tables["ccf.members"]:foreach(function(member, details)
    if details["status"] == STATE_ACTIVE and not is_operator(tostring(member)) then
      members_active = members_active + 1
    end
  end)

  -- check for raw_puts to sensitive tables
  SENSITIVE_TABLES = {"ccf.whitelists", "ccf.gov_scripts"}
  for _, call in pairs(calls) do
    if call.func == "raw_puts" then
      for _, sensitive_table in pairs(SENSITIVE_TABLES) do
        if call.args[sensitive_table] then
          -- require unanimity of non-operating members
          return member_votes == members_active
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
    return true
  end

  -- a single operator can pass an operator vote
  if operator_vote then
    return operator_votes > 0
  end

  return false]],

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
  if tables["ccf.user_certs"]:get(cert) then return end
  NEXT_USER_ID = 1
  user_id = tables["ccf.values"]:get(NEXT_USER_ID)
  tables["ccf.values"]:put(NEXT_USER_ID, user_id + 1)
  tables["ccf.users"]:put(user_id, {cert=cert})
  tables["ccf.user_certs"]:put(cert, user_id)
  ]]
}
