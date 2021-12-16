import { C } from "./sub/foo.js";

export async function test_module() {
  const { bar, getC } = await import("./bar.js");
  if (!(getC() instanceof C)) {
    // happens if foo.js has been compiled multiple times
    // through different import chains
    throw new Error("inconsistent class prototype");
  }
  return { body: bar(), statusCode: 201 };
}
