-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {
  LOG_get = [[
    "LOG_get"
  ]],

  LOG_get_pub = [[
    "LOG_get_pub"
  ]],

  LOG_record = [[
    var a = JSON.parse(args);
    console.log(a.params.id + ": " + a.params.msg)
  ]],

  LOG_record_pub = [[
    "LOG_record_pub"
  ]]
}
