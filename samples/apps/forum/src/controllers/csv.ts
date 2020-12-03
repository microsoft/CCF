// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import {
  SuccessResponse,
  Request,
  Response,
  Controller,
  Security,
  Get,
  Post,
  Route,
} from "@tsoa/runtime";

// Need to use minified browser bundle to avoid pulling in Node.JS dependencies
import { parse, unparse } from "papaparse/papaparse.min";

import {
  ErrorResponse,
  ValidateErrorResponse,
  ValidateError,
  BadRequestError,
  UnauthorizedError,
} from "../error_handler";
import { User } from "../authentication";
import * as ccf from "../types/ccf";
import { kv } from "../models/poll";

// GET  /csv return all opinions of authenticated user as CSV
// POST /csv submits opinions for authenticated user from CSV

@Route("csv")
@Security("jwt")
@Response<ErrorResponse>(UnauthorizedError.Status, "Unauthorized")
@Response<ValidateErrorResponse>(
  ValidateError.Status,
  "Schema validation error"
)
export class CSVController extends Controller {
  private kvPolls: kv.PollMap;

  constructor() {
    super();
    this.kvPolls = kv.getPollMap();
  }

  @SuccessResponse(200, "Opinions of authenticated user in CSV format")
  @Get()
  public getOpinionsAsCSV(@Request() request: ccf.Request): any {
    const user: User = request.user;

    const rows = [];
    this.kvPolls.forEach((poll, topic) => {
      const opinion = poll.opinions[user.userId];
      if (opinion !== undefined) {
        rows.push({ Topic: topic, Opinion: opinion });
      }
    });

    const csv = unparse(rows);

    this.setStatus(200);
    return csv;
  }

  @SuccessResponse(204, "Opinions have been successfully recorded")
  @Response<ErrorResponse>(
    BadRequestError.Status,
    "Opinions were not recorded because either an opinion data type did not match the poll type or a poll with the given topic was not found"
  )
  @Post()
  public submitOpinionsFromCSV(@Request() request: ccf.Request): void {
    const user: User = request.user;

    const rows = parse<any>(request.body.text(), { header: true }).data;

    for (const row of rows) {
      const topic = row.Topic;
      const opinion = row.Opinion;
      const poll = this.kvPolls.get(topic);
      if (poll === undefined) {
        throw new BadRequestError(`Poll with topic '${topic}' does not exist`);
      }
      if (poll.type === "number") {
        const val = Number(opinion);
        if (Number.isNaN(val)) {
          throw new BadRequestError(
            `Opinion for poll with topic '${topic}' could not be parsed as number`
          );
        }
        poll.opinions[user.userId] = val;
      } else {
        poll.opinions[user.userId] = opinion;
      }
      this.kvPolls.set(topic, poll);
    }

    this.setStatus(204);
  }
}
