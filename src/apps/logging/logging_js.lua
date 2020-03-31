-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {
  LOG_get = [[
    function get(query)
    {
      const elements = query.split("&");
      for (kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          return {msg: tables.log.get(JSON.parse(v))};
        }
      }
      throw "Could not find 'id' in query";
    }
    get(query)
  ]],

  LOG_get_pub = [[
    function get(query)
    {
      const elements = query.split("&");
      for (kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          return {msg: tables.log.get(JSON.parse(v))};
        }
      }
      throw "Could not find 'id' in query";
    }
    get(query)
  ]],

  LOG_record = [[
    function record(params)
    {
      tables.log.put(params.id, params.msg);
      return true;
    }
    record(JSON.parse(body))
  ]],

  LOG_record_pub = [[
    function record(params)
    {
      tables.log.put(params.id, params.msg);
      return true;
    }
    record(JSON.parse(body))
  ]]
}