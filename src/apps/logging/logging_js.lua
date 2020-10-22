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
          const msg = ccf.kv.data.get(ccf.strToBuf(v));
          if (msg === undefined) {
            return { body: {error: 'No such key' } };
          }
          return { body: {msg: ccf.bufToStr(msg)} };
        }
      }
      throw new Error("Could not find 'id' in query");
    }
  ]],

  ["GET log/public"] = [[
    export default function(request)
    {
      const elements = request.query.split("&");
      for (const kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          const msg = ccf.kv.data.get(ccf.strToBuf(v));
          if (msg === undefined) {
            return { body: {error: 'No such key' } };
          }
          return { body: {msg: ccf.bufToStr(msg)} };
        }
      }
      throw new Error("Could not find 'id' in query");
    }
  ]],

  ["POST log/private"] = [[
    export default function(request)
    {
      let params = request.body.json();
      ccf.kv.data.set(ccf.strToBuf(params.id.toString()), ccf.strToBuf(params.msg));
      return { body: true };
    }
  ]],

  ["POST log/public"] = [[
    export default function(request)
    {
      let params = request.body.json();
      ccf.kv.data.set(ccf.strToBuf(params.id.toString()), ccf.strToBuf(params.msg));
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
          if (!ccf.kv.data.delete(ccf.strToBuf(v))) 
          {
            return { body: {error: 'No such key'} }
          }
          return { body: true };
        }
      }
      throw new Error("Could not find 'id' in query");
    }
  ]],

  ["DELETE log/private"] = [[
    export default function(request)
    {
      const elements = request.query.split("&");
      for (const kv of elements) {
        const [k, v] = kv.split("=");
        if (k == "id") {
          if (!ccf.kv.data.delete(ccf.strToBuf(v))) 
          {
            return { body: {error: 'No such key'} }
          }
          return { body: true };
        }
      }
      throw new Error("Could not find 'id' in query");
    }
  ]]
}