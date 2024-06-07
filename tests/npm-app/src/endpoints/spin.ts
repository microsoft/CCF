import * as ccfapp from "@microsoft/ccf-app";

interface SpinRequest {
  iterations: number;
}

export function spin(
  request: ccfapp.Request<SpinRequest>,
): ccfapp.Response<boolean> {
  for (let i = 0; i <= request.body.json().iterations; i++) {
    //
  }
  return { body: true };
}
