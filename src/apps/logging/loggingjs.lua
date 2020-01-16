-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {
  LOG_get = [[
    var r = {msg: "Hello world"}
    r
  ]],

  LOG_get_pub = [[
    var r = {msg: "Hello world"}
    r
  ]],

  LOG_record = [[
    function record(params)
    {
      console.log(params.id + ": " + params.msg)
      return true;
    }
    record(JSON.parse(args).params)
  ]],

  LOG_record_pub = [[
    function record(params)
      {
        console.log(params.id + ": " + params.msg)
        return true;
      }
      record(JSON.parse(args).params)
  ]]
}