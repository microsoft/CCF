import "reflect-metadata";
import * as ccfapp from "@microsoft/ccf-app";
import { container } from "./inversify.config";
import { SlowConstructorService } from "./SlowConstructorService";
import { fibonacci } from "./bad_fib";

console.log("Logging at global scope of di");

export function slowCall(request: ccfapp.Request): ccfapp.Response {
  if (globalThis.initialised !== true) {
    console.log("Doing first-time initialisation");
    console.log(`  fibonacci(32) = ${fibonacci(32)}`);
    globalThis.initialised = true;
    console.log("Done first-time initialisation");
  } else {
    console.log("Already initialised");
  }

  console.log("Requesting service");
  const slowConstructed = container.get<SlowConstructorService>(
    SlowConstructorService.ServiceId,
  );
  console.log("Requested service");

  console.log("Requesting service again");
  const slowConstructed2 = container.get<SlowConstructorService>(
    SlowConstructorService.ServiceId,
  );
  console.log("Requested service again");

  return { statusCode: 200 };
}
