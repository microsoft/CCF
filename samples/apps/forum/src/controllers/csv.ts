// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import * as ccfapp from "@microsoft/ccf-app";

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

import {
  ErrorResponse,
  ValidateErrorResponse,
  ValidateError,
  UnauthorizedError,
} from "../error_handler.js";
import { User } from "../authentication.js";
import { CsvService } from "../services/csv.js";

// GET  /csv return all opinions of authenticated user as CSV
// POST /csv submits opinions for authenticated user from CSV

@Route("csv")
@Security("jwt")
@Response<ErrorResponse>(UnauthorizedError.Status, "Unauthorized")
@Response<ValidateErrorResponse>(
  ValidateError.Status,
  "Schema validation error"
)
@Response<ErrorResponse>("default", "Error")
export class CsvController extends Controller {
  private csvService: CsvService;

  constructor() {
    super();
    this.csvService = new CsvService();
  }

  @SuccessResponse(200, "Opinions of authenticated user in CSV format")
  @Get()
  public getOpinionsAsCsv(@Request() request: ccfapp.Request): any {
    const user = <User>request.caller;
    const csv = this.csvService.getOpinions(user.userId);
    this.setStatus(200);
    return csv;
  }

  @SuccessResponse(204, "Opinions have been successfully recorded")
  @Post()
  public submitOpinionsFromCSV(@Request() request: ccfapp.Request): void {
    const user = <User>request.caller;
    const csv = request.body.text();
    this.csvService.submitOpinions(user.userId, csv);
    this.setStatus(204);
  }
}
