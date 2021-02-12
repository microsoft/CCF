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

  -- returns true if the member is a recovery member
  function is_recovery_member(member)
    member_info = tables["public:ccf.gov.members.info"]:get(member)
    if member_info then
      member_enc_pubk = member_info.encryption_pub_key
      if member_enc_pubk then
        return true
      end
    end
    return false
  end

  -- defines which of the members are operators
  function is_operator(member)
    -- Operators cannot be recovery members
    if is_recovery_member(member) then
      return false
    end
    member_info = tables["public:ccf.gov.members.info"]:get(member)
    if member_info then
      member_data = member_info.member_data
      if member_data then
        return member_data.is_operator == true
      end
    end
    return false
  end

  -- defines calls that can be passed with sole operator input
  function can_operator_pass(call)
    -- some calls can always be called by operators
    allowed_operator_funcs = {
      trust_node=true,
      retire_node=true,
      new_node_code=true
    }
    if allowed_operator_funcs[call.func] then
      return true
    end

    -- additionally, operators can add or retire other operators
    if call.func == "new_member" then
      member_data = call.args.member_data
      if member_data and member_data.is_operator then
        return true
      end
    elseif call.func == "retire_member" then
      if is_operator(call.args) then
        return true
      end
    end
  end

  -- count member votes
  member_votes = 0

  for member, vote in pairs(votes) do
    if vote then
      if not is_operator(tonumber(member)) then
        member_votes = member_votes + 1
      end
    end
  end

  -- count active members, excluding operators
  members_active = 0

  tables["public:ccf.gov.members.info"]:foreach(function(member, details)
    if details["status"] == STATE_ACTIVE and not is_operator(member) then
      members_active = members_active + 1
    end
  end)

  -- check for raw_puts to sensitive tables
  SENSITIVE_TABLES = {"public:ccf.gov.whitelists", "public:ccf.gov.scripts"}
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

  -- a proposal is an operator change if it's only making operator calls
  operator_change = true
  for _, call in pairs(calls) do
    if not can_operator_pass(call) then
      operator_change = false
      break
    end
  end

  -- a majority of members can always pass votes
  if member_votes > math.floor(members_active / 2) then
    return PASSED
  end

  -- operators proposing operator changes can pass them without a vote
  if operator_change and is_operator(tonumber(proposer_id)) then
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
}
