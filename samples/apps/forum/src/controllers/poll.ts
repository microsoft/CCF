// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import * as ccfapp from "@microsoft/ccf-app";

import {
  Body,
  Path,
  SuccessResponse,
  Request,
  Response,
  Controller,
  Security,
  Get,
  Post,
  Put,
  Route,
} from "@tsoa/runtime";

import {
  ErrorResponse,
  ValidateErrorResponse,
  ValidateError,
  UnauthorizedError,
} from "../error_handler";
import { User } from "../authentication";
import { Opinion, PollSummary } from "../models/poll";
import { PollService } from "../services/poll";

interface CreatePollRequest {
  type: "string" | "number";
}

interface CreatePollsRequest {
  polls: { [topic: string]: CreatePollRequest };
}

interface SubmitOpinionRequest {
  opinion: Opinion;
}

interface SubmitOpinionsRequest {
  opinions: { [topic: string]: SubmitOpinionRequest };
}

type GetPollResponse = PollSummary;

interface GetPollsResponse {
  polls: { [topic: string]: PollSummary };
}

// Export REST API request/response types for unit tests
export {
  CreatePollRequest,
  SubmitOpinionRequest,
  CreatePollsRequest,
  SubmitOpinionsRequest,
  GetPollResponse,
  GetPollsResponse
};

// GET  /polls/{topic} return poll
// POST /polls/{topic} create poll
// PUT  /polls/{topic} submit opinion
// GET  /polls return all polls
// POST /polls create multiple polls
// PUT  /polls submit opinions for multiple polls

@Route("polls")
@Security("jwt")
@Response<ErrorResponse>(UnauthorizedError.Status, "Unauthorized")
@Response<ValidateErrorResponse>(
  ValidateError.Status,
  "Schema validation error"
)
@Response<ErrorResponse>("default", "Error")
export class PollController extends Controller {
  private pollService: PollService;

  constructor() {
    super();
    this.pollService = new PollService();
  }

  @SuccessResponse(201, "Poll has been successfully created")
  @Post("{topic}")
  public createPoll(
    @Path() topic: string,
    @Body() body: CreatePollRequest,
    @Request() request: ccfapp.Request
  ): void {
    const user = <User>request.caller;
    this.pollService.createPoll(user.userId, topic, body.type);
    this.setStatus(201);
  }

  @SuccessResponse(201, "Polls have been successfully created")
  @Post()
  public createPolls(
    @Body() body: CreatePollsRequest,
    @Request() request: ccfapp.Request
  ): void {
    const user = <User>request.caller;
    const polls = new Map(Object.entries(body.polls).map(
      ([type, poll]) => [type, poll.type]));
    this.pollService.createPolls(user.userId, polls);
    this.setStatus(201);
  }

  @SuccessResponse(204, "Opinion has been successfully recorded")
  @Put("{topic}")
  public submitOpinion(
    @Path() topic: string,
    @Body() body: SubmitOpinionRequest,
    @Request() request: ccfapp.Request
  ): void {
    const user = <User>request.caller;
    this.pollService.submitOpinion(user.userId, topic, body.opinion);
    this.setStatus(204);
  }

  @SuccessResponse(204, "Opinions have been successfully recorded")
  @Put()
  public submitOpinions(
    @Body() body: SubmitOpinionsRequest,
    @Request() request: ccfapp.Request
  ): void {
    const user = <User>request.caller;
    const opinions = new Map(Object.entries(body.opinions).map(
      ([topic, opinion]) => [topic, opinion.opinion]));
    this.pollService.submitOpinions(user.userId, opinions);
    this.setStatus(204);
  }

  @SuccessResponse(200, "Poll summary")
  @Get("{topic}")
  public getPoll(
    @Path() topic: string,
    @Request() request: ccfapp.Request
  ): GetPollResponse {
    const user = <User>request.caller;
    const summary = this.pollService.getPollSummary(user.userId, topic);
    this.setStatus(200);
    return summary;
  }

  @SuccessResponse(200, "Poll summaries")
  @Get()
  public getPolls(@Request() request: ccfapp.Request): GetPollsResponse {
    const user = <User>request.caller;
    const summaries = this.pollService.getPollSummaries(user.userId);

    const response: GetPollsResponse = { polls: {} };
    for (const [topic, summary] of summaries.entries()) {
      response.polls[topic] = summary;
    }

    this.setStatus(200);
    return response;
  }
}
