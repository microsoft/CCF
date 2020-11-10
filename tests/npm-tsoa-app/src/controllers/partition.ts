import { Body, Controller, Post, Route } from "@tsoa/runtime";

import * as _ from "lodash-es";

type PartitionRequest = any[];
type PartitionResponse = any[][];

@Route("partition")
export class PartitionController extends Controller {
  @Post()
  public computePartition(@Body() body: PartitionRequest): PartitionResponse {
    return _.partition(body, (n) => n % 2);
  }
}
