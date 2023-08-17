import { fibonacci } from "./bad_fib.js";

// TODO: Document that this is _NOT_ what apps should be doing, just done here to test precise caching behaviour
export function cachedFib(request) {
  if (!(globalThis.BadCache instanceof Object)) {
    globalThis.BadCache = {};
  }

  const body = request.body.json();
  const n = body.n;
  var wasCached = true;

  if (!(n in globalThis.BadCache)) {
    const fib = fibonacci(n);
    console.log(`Calculated fibonacci(${n}) = ${fib}`);
    globalThis.BadCache[n] = fib;
    wasCached = false;
  }

  return { body: { fib: globalThis.BadCache[n], wasCached: wasCached } };
}
