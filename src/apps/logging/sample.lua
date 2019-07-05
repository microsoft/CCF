-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {
  __environment = [[
    env = {
      error_codes = {
        PARSE_ERROR = -32700,
        INVALID_REQUEST = -32600,
        METHOD_NOT_FOUND = -32601,
        INVALID_PARAMS = -32602,
        INTERNAL_ERROR = -32603,
        INVALID_CLIENT_SIGNATURE = -32605,
        INVALID_CALLER_ID = -32606,

        INSUFFICIENT_RIGHTS = -32006,
        DENIED = -32007
      }
    }

    -- tables.priv0: Transactions
    --    tx_id         -> [src, dst, amt, type, bank_id, src_country, dst_country]
    -- tables.priv1: Regulator
    --    regulator_id  -> [country, lua checker]
    -- tables.priv2: Flagged Transactions
    --    tx_id         -> [country, revealed]


    -- tables.priv3: Regulator ID (to uniquely identify a regulator)
    --    0             -> [regulator_id]
    -- tables.priv4: Bank ID (to uniquely identify a bank)
    --    0             -> [bank_id]

    function env.jsucc(result)
      return {result = result}
    end

    function env.jerr(code, message)
      return {error = {code = code, message = message}}
    end

    -- TODO: For now, regulator id is a global variable
    current_regulator_id = 0

    --
    -- Transaction functions
    --

    function env.record_transaction()
      tables.priv0:put(args.params.id, {args.params.src, args.params.dst, args.params.amt})
      return env.jsucc(true)
    end

    function env.get_transaction()
      tx_v = tables.priv0:get(args.params.id)
      if not tx_v then
        return env.jerr(env.error_codes.INVALID_PARAMS, "No such transaction")
      end
      return env.jsucc(tx_v)
    end

    --
    -- Regulator functions
    --

    -- custom functions for sample application

    function env.record_regulator()
      current_regulator_id = current_regulator_id + 1
      tables.priv1:put(current_regulator_id, args.params.country)
      return env.jsucc(true)
    end

    function env.get_regulator()
      country = tables.priv1:get(args.params.id)
      if not country then
        return env.jerr(env.error_codes.INVALID_PARAMS, "No such registrator")
      end
      return env.jsucc(country)
    end
  ]],

  TX_record = [[
    -- SNIPPET_START: lua_params
    tables, gov_tables, args = ...
    -- SNIPPET_END: lua_params
    return env.record_transaction()
  ]],

  TX_get = [[
    -- SNIPPET_START: lua_params
    tables, gov_tables, args = ...
    -- SNIPPET_END: lua_params
    return env.get_transaction()
  ]],

  REG_record = [[
    tables, gov_tables, args = ...
    return env.record_regulator()
  ]],

  REG_get = [[
    tables, gov_tables, args = ...
    return env.get_regulator()
  ]],
}
