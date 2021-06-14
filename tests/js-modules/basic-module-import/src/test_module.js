import { bar, getC } from "./bar.js";
import { C } from "./sub/foo.js";

export function test_module() {
  if (!(getC() instanceof C)) {
    // happens if foo.js has been compiled multiple times
    // through different import chains
    throw new Error("inconsistent class prototype");
  }
  return { body: bar(), statusCode: 201 };
}
