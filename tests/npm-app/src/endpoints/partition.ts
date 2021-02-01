import * as _ from "lodash-es";

import * as ccf from "../types/ccf";

type PartitionRequest = any[];
type PartitionResponse = [any[], any[]];

export function partition(
  request: ccf.Request<PartitionRequest>
): ccf.Response<PartitionResponse> {
  // Example from https://lodash.com.
  let arr = request.body.json();
  return { body: _.partition(arr, (n) => n % 2) };
}
