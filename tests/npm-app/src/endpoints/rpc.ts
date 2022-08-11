import * as ccfapp from "@microsoft/ccf-app";

export function postApplyWrites(request: ccfapp.Request): ccfapp.Response {
  const kv = ccfapp.typedKv(
    "public:apply_writes",
    ccfapp.string,
    ccfapp.string
  );
  const params = request.body.json();
  kv.set("foo", params.val);
  if ("setApplyWrites" in params) {
    ccfapp.setApplyWrites(params.setApplyWrites);
  }
  return {
    statusCode: params.statusCode,
  };
}

export function getApplyWrites(request: ccfapp.Request): ccfapp.Response {
  const kv = ccfapp.typedKv(
    "public:apply_writes",
    ccfapp.string,
    ccfapp.string
  );
  const v = kv.get("foo");
  return {
    body: v,
  };
}
