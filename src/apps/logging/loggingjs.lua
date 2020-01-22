-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {
  LOG_get = [[
    function get(params)
    {
      return {msg: tables.log.get(params.id)};
    }
    get(JSON.parse(args).params)
  ]],

  LOG_get_pub = [[
    function get(params)
    {
      return {msg: tables.log.get(params.id)};
    }
    get(JSON.parse(args).params)
  ]],

  LOG_record = [[
    function record(params)
    {
      tables.log.put(params.id, params.msg);
      return true;
    }
    record(JSON.parse(args).params)
  ]],

  LOG_record_pub = [[
    function record(params)
    {
      tables.log.put(params.id, params.msg);
      return true;
    }
    record(JSON.parse(args).params)
  ]]
}