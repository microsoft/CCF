import { foo, C } from "./sub/foo.js";

export function bar() {
  return foo();
}

export function getC() {
  return new C();
}
