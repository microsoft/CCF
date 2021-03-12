import * as _ from "lodash-es";

import { Request, Response } from "../ccf/builtin";

type PartitionRequest = any[];
type PartitionResponse = [any[], any[]];

export function partition(
  request: Request<PartitionRequest>
): Response<PartitionResponse> {
  // Example from https://lodash.com.
  let arr = request.body.json();
  return { body: _.partition(arr, (n) => n % 2) };
}
