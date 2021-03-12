import * as _ from "lodash-es";

import { CCF } from "../ccf/builtin";

type PartitionRequest = any[];
type PartitionResponse = [any[], any[]];

export function partition(
  request: CCF.Request<PartitionRequest>
): CCF.Response<PartitionResponse> {
  // Example from https://lodash.com.
  let arr = request.body.json();
  return { body: _.partition(arr, (n) => n % 2) };
}
