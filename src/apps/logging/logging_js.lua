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
          try
          {
            return {msg: tables.data.get(JSON.parse(v).toString())};
          }
          catch (err)
          {
            return {error: err.message}
          }
        }
      }
      throw "Could not find 'id' in query";
    }
    get(query)
  ]],

  LOG_remove = [[
    function remove(query)
    {
      const elements = query.split("&");
      for (kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          return tables.data.remove(JSON.parse(v).toString());
        }
      }
      throw "Could not find 'id' in query";
    }
    remove(query)
  ]],

  LOG_get_pub = [[
    function get(query)
    {
      const elements = query.split("&");
      for (kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          return {msg: tables.data.get(JSON.parse(v).toString())};
        }
      }
      throw "Could not find 'id' in query";
    }
    get(query)
  ]],

  LOG_record = [[
    function record(params)
    {
      tables.data.put(params.id.toString(), params.msg);
      return true;
    }
    record(JSON.parse(body))
  ]],

  LOG_record_pub = [[
    function record(params)
    {
      tables.data.put(params.id.toString(), params.msg);
      return true;
    }
    record(JSON.parse(body))
  ]]
}