import * as ccfapp from "@microsoft/ccf-app";
import { SlowConstructorService } from "./SlowConstructorService";
import { getSingleton } from "./singleton_service_registry";

// Demonstrates impact of interpreter reuse on application-level singleton
// service patterns. With fresh interpreters, module-level state is rebuilt each
// time, leading to repeated unnecessary construction costs. By reusing existing
// interpreters, where this module state is retained, we can see a significant
// perf speedup.
export function slowCall(request: ccfapp.Request): ccfapp.Response {
  console.log("Requesting service");
  const slowConstructed = getSingleton(
    SlowConstructorService.ServiceId,
    () => new SlowConstructorService(),
  );
  console.log("Requested service");

  console.log("Requesting service again");
  const slowConstructed2 = getSingleton(
    SlowConstructorService.ServiceId,
    () => new SlowConstructorService(),
  );
  console.log("Requested service again");

  return { statusCode: 200 };
}
