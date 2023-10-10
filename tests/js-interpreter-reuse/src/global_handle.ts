import * as ccfapp from "@microsoft/ccf-app";

function increment() {
  if (!('kvHandle' in globalThis)) {
    globalThis.kvHandle = ccfapp.typedKv(
      "public:cached_handle_table",
      ccfapp.string,
      ccfapp.uint32
    );
  }

  const k = "single_key";
  if (!globalThis.kvHandle.has(k))
  {
    globalThis.kvHandle.set(k, 0);
  }
  else
  {
    const v = globalThis.kvHandle.get(k);
    globalThis.kvHandle.set(k, v + 1);
  }

  const v = globalThis.kvHandle.get(k);
  
  return { body: { value: v } };
}

export { increment };
