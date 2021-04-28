import { bar } from "./bar.js";

export function test_module() {
  return { body: bar(), statusCode: 201 };
}
