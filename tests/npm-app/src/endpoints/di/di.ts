import "reflect-metadata";
import * as ccfapp from "@microsoft/ccf-app";
import { container } from "./inversify.config";
import { SlowConstructorService } from "./SlowConstructorService";
import { fibonacci } from "./bad_fib";

var initialised;

export function getFaster(request: ccfapp.Request): ccfapp.Response {
  if (initialised !== true) {
    console.log("Doing first-time initialisation");
    console.log(`  fibonacci(32) = ${fibonacci(32)}`);
    initialised = true;
    console.log("Done first-time initialisation");
  }

  console.log("Requesting service");
  const slowConstructed = container.get<SlowConstructorService>(
    SlowConstructorService.ServiceId
  );
  console.log("Requested service");

  return { statusCode: 200 };
}
