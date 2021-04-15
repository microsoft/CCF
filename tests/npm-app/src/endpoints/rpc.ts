import * as ccfapp from "@microsoft/ccf-app";

export function applyWrites(request: ccfapp.Request): ccfapp.Response {
  const kv = ccfapp.typedKv(
    "public:apply_writes",
    ccfapp.string,
    ccfapp.string
  );
  kv.set("foo", "bar");
  ccfapp.setApplyWrites(true);
  return {
    statusCode: 400,
  };
}
