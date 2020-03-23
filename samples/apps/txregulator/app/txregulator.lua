-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {
  __environment = [[
      env.transaction_type = {
        PAYMENT = 1,
        TRANSFER = 2,
        CASH_OUT = 3,
        DEBIT = 4,
        CASH_IN = 5
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
    --    tx_id         -> [src, dst, amt, type, bank_id, src_country, dst_country, timestamp]
    function env.tx_table()
      return tables.priv0
    end

    -- Regulators table:
    --    regulator_id  -> [country, lua checker]
    function env.reg_table()
      return tables.priv1
    end

    -- Bank table:
    --    bank_id       -> [country]
    function env.bank_table()
      return tables.priv2
    end

    -- Flagged transactions:
    --    tx_id        ->  [regulator id, revealed, timestamp, regulator name]
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

    function env.get_privileges(caller_id)
      local users_table = gov_tables["ccf.users"]
      local user_info = users_table:get(caller_id)
      if user_info ~= nil then
        local user_data = user_info.user_data
        if user_data ~= nil then
          return user_data.privileges
        end
      end
      return nil
    end

    function env.can_register_regulators(caller_id)
      local privileges = env.get_privileges(caller_id)
      if privileges ~= nil then
        return privileges.REGISTER_REGULATORS == true
      end
      return false
    end

    function env.can_register_banks(caller_id)
      local privileges = env.get_privileges(caller_id)
      if privileges ~= nil then
        return privileges.REGISTER_BANKS == true
      end
      return false
    end

    --
    --  BANK ENDPOINTS
    --

    function env.record_transaction()
      bank_v = env.bank_table():get(args.caller_id)
      if not bank_v then
        return env.jerr(env.error_codes.FORBIDDEN, "User is not registered as a bank")
      end

      table_entries = {bank_id=args.caller_id}
      for k,v in pairs(args.params) do
        table_entries[k] = v
      end

      env.tx_table():put(tx_id, table_entries)

      tx_id = env.get_next_tx_id()
      env.tx_table():put(tx_id, table_entries)

      reg_table = env.reg_table()
      flagged_table = env.flagged_tx()

      -- reg_table: key-> regulator id, value -> (src_country, script, name)
      reg_table:foreach(
        function (k, v) flagged = env.run_checker(tx_id, v[2]);
          if flagged then flagged_table:put(tx_id, {k, false, args.params.timestamp, v[3]}) end
        end
      )
      return env.jsucc(tx_id)
    end

    function env.get_transaction()
      tx_v = env.tx_table():get(args.params.tx_id)
      if not tx_v then
        return env.jerr(env.error_codes.BAD_REQUEST, "No such transaction")
      end
      if tx_v.bank_id ~= args.caller_id then
        return env.jerr(env.error_codes.FORBIDDEN, "Transaction was not issued by you.")
      end
      return env.jsucc(tx_v)
    end

    function env.get_revealed_transaction()
      tx_id = args.params.tx_id
      flagged_table = env.flagged_tx()
      flagged_v = flagged_table:get(tx_id)
      if not flagged_v then
        return env.jerr(env.error_codes.BAD_REQUEST, "Transaction has not been flagged")
      end

      if not flagged_v[2] then
        return env.jerr(env.error_codes.BAD_REQUEST, "Transaction has not been revealed")
      end

      tx_v = env.tx_table():get(tx_id)

      -- remove the transaction from the flagged_tx table
      flagged_table:put(tx_id, {})
      
      tx = {tx_id=tx_id}
      for k, v in pairs(tx_v) do
        tx[k] = v
      end

      return env.jsucc(tx)
    end

    function env.register_bank()
      if not env.can_register_banks(args.caller_id) then
        return env.jerr(env.error_codes.FORBIDDEN, "User " .. args.caller_id .. " is not permitted to register new banks")
      end

      local bank_id = args.params.bank_id
      reg_v = env.reg_table():get(bank_id)
      if reg_v then
        return env.jerr(env.error_codes.BAD_REQUEST, "User " .. bank_id .. " is already registered as a regulator - not permitted to also be a bank")
      end
      env.bank_table():put(bank_id, args.params.country)
      return env.jsucc(bank_id)
    end

    function env.get_bank()
      bank_v = env.bank_table():get(args.params.id)
      if not bank_v then
        return env.jerr(env.error_codes.BAD_REQUEST, "No such bank")
      end
      return env.jsucc(bank_v)
    end

    function env.reveal_transaction()
      tx_id = args.params.tx_id
      tx_v = env.tx_table():get(tx_id)
      if not tx_v then
        return env.jerr(env.error_codes.BAD_REQUEST, "No such transaction")
      end

      -- TODO: For now, anyone can reveal transactions
      -- if tx_v[1] ~= args.caller_id then
      --   return env.jerr(env.error_codes.FORBIDDEN, "Transaction was not issued by you")
      -- end

      flagged_table = env.flagged_tx()
      flagged_v = flagged_table:get(tx_id)
      if not flagged_v then
        return env.jerr(env.error_codes.BAD_REQUEST, "Transaction has not been flagged")
      end
      flagged_v[2] = true
      flagged_table:put(tx_id, flagged_v)
      return env.jsucc(true)
    end

    --
    --  REGULATOR ENDPOINTS
    --

    function env.register_regulator()
      if not env.can_register_regulators(args.caller_id) then
        return env.jerr(env.error_codes.FORBIDDEN, "User " .. args.caller_id .. " is not permitted to register new regulators")
      end

      local reg_id = args.params.regulator_id
      bank_v = env.bank_table():get(reg_id)
      if bank_v then
        return env.jerr(env.error_codes.BAD_REQUEST, "User " .. reg_id .. " is already registered as a bank - not permitted to also be a regulator")
      end
      env.reg_table():put(reg_id, {args.params.country, args.params.script, args.params.name})
      return env.jsucc(reg_id)
    end

    function env.get_regulator()
      reg_v = env.reg_table():get(args.params.id)
      if not reg_v then
        return env.jerr(env.error_codes.BAD_REQUEST, "No such regulator")
      end
      return env.jsucc(reg_v)
    end

    function env.run_checker(tx_id, script)
      dst = args.params.dst
      amt = args.params.amt
      tx_type = args.params.type
      src_country = args.params.src_country
      dst_country = args.params.dst_country
      f = load(script);
      return f()
    end

    function env.poll_flagged()
      reg_v = env.reg_table():get(args.caller_id)
      if not reg_v then
        return env.jerr(env.error_codes.FORBIDDEN, "User is not registered as a regulator")
      end
      tx_ids = {}
      env.flagged_tx():foreach(
        function (k, v) if next(v) then table.insert(tx_ids, {k, v[1], v[4]}) end end
      )
      return env.jsucc(tx_ids)
    end

    function env.get_revealed()
      reg_v = env.reg_table():get(args.caller_id)
      if not reg_v then
        return env.jerr(env.error_codes.FORBIDDEN, "User is not registered as a regulator")
      end
      return(env.get_revealed_transaction())
    end

    --
    --  FLAGGED TX ENDPOINTS
    --

    function env.get_flagged_tx()
      flagged_tx = env.flagged_tx():get(args.params.tx_id)
      if not flagged_tx then
        return env.jerr(env.error_codes.BAD_REQUEST, "No such transaction")
      end
      return env.jsucc(flagged_tx)
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
    return env.reveal_transaction()
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

  REG_poll_flagged = [[
    tables, gov_tables, args = ...
    return env.poll_flagged()
  ]],

  REG_get_revealed = [[
    tables, gov_tables, args = ...
    return env.get_revealed()
  ]],

  FLAGGED_TX_get = [[
    tables, gov_tables, args = ...
    return env.get_flagged_tx()
  ]],
}
