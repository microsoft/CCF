import * as ccfapp from "@microsoft/ccf-app";

type PartitionRequest = any[];
type PartitionResponse = [any[], any[]];

export function partition(
  request: ccfapp.Request<PartitionRequest>,
): ccfapp.Response<PartitionResponse> {
  // Example from https://lodash.com.
  let arr = request.body.json();
  const matching = [];
  const nonMatching = [];

  for (const n of arr) {
    if (n % 2) {
      matching.push(n);
    } else {
      nonMatching.push(n);
    }
  }

  return { body: [matching, nonMatching] };
}
