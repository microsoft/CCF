import * as _ from "lodash-es";

import * as ccfapp from "ccf-app";

type PartitionRequest = any[];
type PartitionResponse = [any[], any[]];

export function partition(
  request: ccfapp.Request<PartitionRequest>
): ccfapp.Response<PartitionResponse> {
  // Example from https://lodash.com.
  let arr = request.body.json();
  return { body: _.partition(arr, (n) => n % 2) };
}
