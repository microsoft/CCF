-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {
  ["GET log/private"] = [[
    export default function()
    {
      const elements = query.split("&");
      for (const kv of elements) {
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
  ]],

  ["GET log/public"] = [[
    export default function()
    {
      const elements = query.split("&");
      for (const kv of elements) {
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
  ]],

  ["POST log/private"] = [[
    export default function()
    {
      let params = body.json();
      tables.data.put(params.id.toString(), params.msg);
      return true;
    }
  ]],

  ["POST log/public"] = [[
    export default function()
    {
      let params = body.json();
      tables.data.put(params.id.toString(), params.msg);
      return true;
    }
  ]],

  ["DELETE log/public"] = [[
    export default function()
    {
      const elements = query.split("&");
      for (const kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          return tables.data.remove(JSON.parse(v).toString());
        }
      }
      throw "Could not find 'id' in query";
    }
  ]],

  ["DELETE log/private"] = [[
    export default function()
    {
      const elements = query.split("&");
      for (const kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          return tables.data.remove(JSON.parse(v).toString());
        }
      }
      throw "Could not find 'id' in query";
    }
  ]]
}