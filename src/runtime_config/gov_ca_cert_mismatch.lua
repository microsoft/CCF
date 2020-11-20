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

  -- CA cert validation definitions
  -- This SIGNER_ID is intentially random and does not match the actual certificate.
  -- See the governance_ca_cert_mismatch.py test.
  EXPECTED_SIGNER_ID = "abcd"
  EXPECTED_ATTRIBUTES = "0300000000000000"

  -- count member votes
  member_votes = 0

  for member, vote in pairs(votes) do
    if vote then
      member_votes = member_votes + 1
    end
  end

  -- count active members
  members_active = 0

  tables["public:ccf.gov.members"]:foreach(function(member, details)
    if details["status"] == STATE_ACTIVE then
      members_active = members_active + 1
    end
  end)

  -- check for raw_puts to sensitive tables
  SENSITIVE_TABLES = {"public:ccf.gov.whitelists", "public:ccf.gov.governance.scripts"}
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

  -- validate update_ca_cert calls
  for _, call in pairs(calls) do
    if call.func == "update_ca_cert" then
      cert_der = pem_to_der(call.args.cert)
      claims = verify_cert_and_get_claims(cert_der)
      if claims.signer_id ~= EXPECTED_SIGNER_ID then
        LOG_INFO("signer_id mismatch: ", EXPECTED_SIGNER_ID, " != ", claims.signer_id)
        return REJECTED
      end
      if claims.attributes ~= EXPECTED_ATTRIBUTES then
        LOG_INFO("attributes mismatch: ", EXPECTED_ATTRIBUTES, " != ", claims.attributes)
        return REJECTED
      end
      return PASSED
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

  function __Calls:empty()
    return self
  end
  Calls = setmetatable({}, {__index = __Calls, __was_object=false})
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

  update_ca_cert = [[
  tables, args = ...
  t = tables["public:ccf.gov.ca_cert_ders"]
  cert_der = pem_to_der(args.cert)
  t:put(args.name, cert_der)
  return true
  ]],
}
