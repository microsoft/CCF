-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

return {
  ["GET log/private"] = [[
    export default function(request)
    {
      const elements = request.query.split("&");
      for (const kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          try
          {
            return { body: {msg: tables.data.get(JSON.parse(v).toString())} };
          }
          catch (err)
          {
            return { body: {error: err.message} };
          }
        }
      }
      throw "Could not find 'id' in query";
    }
  ]],

  ["GET log/public"] = [[
    export default function(request)
    {
      const elements = request.query.split("&");
      for (const kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          try
          {
            return { body: {msg: tables.data.get(JSON.parse(v).toString())} };
          }
          catch (err)
          {
            return { body: {error: err.message} }
          }
        }
      }
      throw "Could not find 'id' in query";
    }
  ]],

  ["POST log/private"] = [[
    export default function(request)
    {
      let params = request.body.json();
      tables.data.put(params.id.toString(), params.msg);
      return { body: true };
    }
  ]],

  ["POST log/public"] = [[
    export default function(request)
    {
      let params = request.body.json();
      tables.data.put(params.id.toString(), params.msg);
      return { body: true };
    }
  ]],

  ["DELETE log/public"] = [[
    export default function(request)
    {
      const elements = request.query.split("&");
      for (const kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          return { body: tables.data.remove(JSON.parse(v).toString()) };
        }
      }
      throw "Could not find 'id' in query";
    }
  ]],

  ["DELETE log/private"] = [[
    export default function(request)
    {
      const elements = request.query.split("&");
      for (const kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          return { body: tables.data.remove(JSON.parse(v).toString()) };
        }
      }
      throw "Could not find 'id' in query";
    }
  ]]
}