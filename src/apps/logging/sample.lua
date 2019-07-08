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

    function env.jsucc(result)
      return {result = result}
    end

    function env.jerr(code, message)
      return {error = {code = code, message = message}}
    end

    --
    -- TABLES
    --

    -- Transactions table:
    --    tx_id         -> [src, dst, amt, type, src_country, dst_country]
    function env.tx_table()
      return tables.priv0
    end

    -- Regulators table:
    --    regulator_id  -> [country, lua checker] TODO: Add Lua checker script
    function env.reg_table()
      return tables.priv1
    end

    -- Bank table:
    --    bank_id       -> [country]
    function env.bank_table()
      return tables.priv2
    end

    -- Flagged transactions:
    --    tx_id        ->  [country, revealed]
    function env.flagged_tx()
      return tables.priv3
    end

    -- Transaction ID:
    --    0           -> tx_id
    function env.get_next_tx_id()
      tx_id = tables.priv4:get(0)
      -- For the first tx, initialise tx_id table
      if not tx_id then
        tables.priv4:put(0, 1)
        return 0
      end
      tables.priv4:put(0, tx_id + 1)
      return tx_id
    end

    --
    --  BANK ENDPOINTS
    --

    function env.record_transaction()
      bank_v = env.bank_table():get(args.caller_id)
      if not bank_v then
        return env.jerr(env.error_codes.INVALID_CALLER_ID, "User is not registered as a bank")
      end

      tx_id = env.get_next_tx_id()
      env.tx_table():put(tx_id,
        {args.caller_id,
        args.params.dst,
        args.params.amt,
        args.params.type,
        args.params.src_country,
        args.params.dst_country})

      -- TODO: Run script for all regulators and add to table_flagged_tx is script returns true
      return env.jsucc(tx_id)
    end

    function env.get_transaction()
      tx_v = env.tx_table():get(args.params.tx_id)
      if not tx_v then
        return env.jerr(env.error_codes.INVALID_PARAMS, "No such transaction")
      end
      if tx_v[1] ~= args.caller_id then
        return env.jerr(env.error_codes.INVALID_CALLER_ID, "Transaction was not issued by you.")
      end
      return env.jsucc(tx_v)
    end

    function env.register_bank()
      reg_v = env.reg_table():get(args.caller_id)
      if reg_v then
        return env.jerr(env.error_codes.INVALID_CALLER_ID, "User is already registered as a regulator")
      end
      env.bank_table():put(args.caller_id, args.params.country)
      return env.jsucc(args.caller_id)
    end

    function env.get_bank()
      bank_v = env.bank_table():get(args.params.id)
      if not bank_v then
        return env.jerr(env.error_codes.INVALID_PARAMS, "No such bank")
      end
      return env.jsucc(bank_v)
    end

    -- function env.reveal_transaction()
    --   -- TODO:
    -- end

    --
    --  REGULATOR ENDPOINTS
    --

    function env.register_regulator()
      bank_v = env.bank_table():get(args.caller_id)
      if bank_v then
        return env.jerr(env.error_codes.INVALID_CALLER_ID, "User is already registered as a bank")
      end

      -- TODO: Record lua script as well
      env.reg_table():put(args.caller_id, args.params.country)
      return env.jsucc(args.caller_id)
    end

    function env.get_regulator()
      reg_v = env.reg_table():get(args.params.id)
      if not reg_v then
        return env.jerr(env.error_codes.INVALID_PARAMS, "No such regulator")
      end
      return env.jsucc(reg_v)
    end

  ]],

  TX_record = [[
    tables, gov_tables, args = ...
    return env.record_transaction()
  ]],

  TX_get = [[
    tables, gov_tables, args = ...
    return env.get_transaction()
  ]],

  TX_reveal = [[
    tables, gov_tables, args = ...
    -- return env.get_transaction()
  ]],

  BK_register = [[
    tables, gov_tables, args = ...
    return env.register_bank()
  ]],

  BK_get = [[
    tables, gov_tables, args = ...
    return env.get_bank()
  ]],

  REG_register = [[
    tables, gov_tables, args = ...
    return env.register_regulator()
  ]],

  REG_get = [[
    tables, gov_tables, args = ...
    return env.get_regulator()
  ]],
}
