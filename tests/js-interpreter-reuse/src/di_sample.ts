import * as ccfapp from "@microsoft/ccf-app";
import { container } from "./inversify.config";
import { SlowConstructorService } from "./SlowConstructorService";

// Demonstrates impact of interpreter reuse on dependency injection patterns,
// such as inversify.
// With fresh interpreters, the DI container must also be freshly constructed
// each time, leading to repeated unnecessary construction costs. By reusing
// existing interpreters, where this container's static state has been stashed
// on the global object, we can see a significant perf speedup.
export function slowCall(request: ccfapp.Request): ccfapp.Response {
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
