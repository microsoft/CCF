// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import * as ccfapp from "ccf-app";

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

import * as _ from "lodash-es";
import * as math from "mathjs";

import {
  ErrorResponse,
  ValidateErrorResponse,
  ValidateError,
  BadRequestError,
  ForbiddenError,
  NotFoundError,
  UnauthorizedError,
} from "../error_handler";
import { User } from "../authentication";
import { PollMap, getPollMap } from "../models/poll";

export const MINIMUM_OPINION_THRESHOLD = 10;

interface CreatePollRequest {
  type: "string" | "number";
}

interface CreatePollsRequest {
  polls: { [topic: string]: CreatePollRequest };
}

type Opinion = string | number;

interface SubmitOpinionRequest {
  opinion: Opinion;
}

interface SubmitOpinionsRequest {
  opinions: { [topic: string]: SubmitOpinionRequest };
}

interface StringPollResponse {
  type: "string";
  statistics?: {
    counts: { [opinion: string]: number };
  };
  opinion?: string;
}

interface NumericPollResponse {
  type: "number";
  statistics?: {
    mean: number;
    std: number;
  };
  opinion?: number;
}

type GetPollResponse = StringPollResponse | NumericPollResponse;

interface GetPollsResponse {
  polls: { [topic: string]: GetPollResponse };
}

// Export REST API request/response types for unit tests
export {
  CreatePollRequest,
  SubmitOpinionRequest,
  CreatePollsRequest,
  SubmitOpinionsRequest,
  GetPollResponse,
  StringPollResponse,
  NumericPollResponse,
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
export class PollController extends Controller {
  private kvPolls: PollMap;

  constructor() {
    super();
    this.kvPolls = getPollMap();
  }

  @SuccessResponse(201, "Poll has been successfully created")
  @Response<ErrorResponse>(
    ForbiddenError.Status,
    "Poll has not been created because a poll with the same topic exists already"
  )
  @Post("{topic}")
  public createPoll(
    @Path() topic: string,
    @Body() body: CreatePollRequest,
    @Request() request: ccfapp.Request
  ): void {
    const user = <User>request.caller;

    if (this.kvPolls.has(topic)) {
      throw new ForbiddenError("Poll with given topic exists already");
    }
    this.kvPolls.set(topic, {
      creator: user.userId,
      type: body.type,
      opinions: {},
    });
    this.setStatus(201);
  }

  @SuccessResponse(201, "Polls have been successfully created")
  @Response<ErrorResponse>(
    ForbiddenError.Status,
    "Polls were not created because a poll with the same topic exists already"
  )
  @Post()
  public createPolls(
    @Body() body: CreatePollsRequest,
    @Request() request: ccfapp.Request
  ): void {
    const user = <User>request.caller;

    for (let [topic, poll] of Object.entries(body.polls)) {
      if (this.kvPolls.has(topic)) {
        throw new ForbiddenError(`Poll with topic '${topic}' exists already`);
      }
      this.kvPolls.set(topic, {
        creator: user.userId,
        type: poll.type,
        opinions: {},
      });
    }
    this.setStatus(201);
  }

  @SuccessResponse(204, "Opinion has been successfully recorded")
  @Response<ErrorResponse>(
    BadRequestError.Status,
    "Opinion was not recorded because the opinion data type does not match the poll type"
  )
  @Response<ErrorResponse>(
    NotFoundError.Status,
    "Opinion was not recorded because no poll with the given topic exists"
  )
  @Put("{topic}")
  public submitOpinion(
    @Path() topic: string,
    @Body() body: SubmitOpinionRequest,
    @Request() request: ccfapp.Request
  ): void {
    const user = <User>request.caller;

    const poll = this.kvPolls.get(topic);
    if (poll === undefined) {
      throw new NotFoundError("Poll does not exist");
    }
    if (typeof body.opinion !== poll.type) {
      throw new BadRequestError("Poll has a different opinion type");
    }
    poll.opinions[user.userId] = body.opinion;
    this.kvPolls.set(topic, poll);
    this.setStatus(204);
  }

  @SuccessResponse(204, "Opinions have been successfully recorded")
  @Response<ErrorResponse>(
    BadRequestError.Status,
    "Opinions were not recorded because either an opinion data type did not match the poll type or a poll with the given topic was not found"
  )
  @Put()
  public submitOpinions(
    @Body() body: SubmitOpinionsRequest,
    @Request() request: ccfapp.Request
  ): void {
    const user = <User>request.caller;

    for (const [topic, opinion] of Object.entries(body.opinions)) {
      const poll = this.kvPolls.get(topic);
      if (poll === undefined) {
        throw new BadRequestError(`Poll with topic '${topic}' does not exist`);
      }
      if (typeof opinion.opinion !== poll.type) {
        throw new BadRequestError(
          `Poll with topic '${topic}' has a different opinion type`
        );
      }
      poll.opinions[user.userId] = opinion.opinion;
      this.kvPolls.set(topic, poll);
    }

    this.setStatus(204);
  }

  @SuccessResponse(200, "Poll data")
  @Response<ErrorResponse>(
    NotFoundError.Status,
    "Poll data could not be returned because no poll with the given topic exists"
  )
  @Get("{topic}")
  public getPoll(
    @Path() topic: string,
    @Request() request: ccfapp.Request
  ): GetPollResponse {
    const user = <User>request.caller;

    if (!this.kvPolls.has(topic)) {
      throw new NotFoundError("Poll does not exist");
    }

    this.setStatus(200);
    return this._getPoll(user.userId, topic);
  }

  @SuccessResponse(200, "Poll data")
  @Get()
  public getPolls(@Request() request: ccfapp.Request): GetPollsResponse {
    const user = <User>request.caller;

    let response: GetPollsResponse = { polls: {} };

    for (const topic of this._getTopics()) {
      response.polls[topic] = this._getPoll(user.userId, topic);
    }

    this.setStatus(200);
    return response;
  }

  _getTopics(): string[] {
    const topics = [];
    this.kvPolls.forEach((val, key) => {
      topics.push(key);
    });
    return topics;
  }

  _getPoll(user: string, topic: string): GetPollResponse {
    const poll = this.kvPolls.get(topic);
    if (poll === undefined) {
      throw new Error(`BUG: poll with topic '${topic}' does not exist`);
    }

    const opinionCountAboveThreshold =
      Object.keys(poll.opinions).length >= MINIMUM_OPINION_THRESHOLD;

    const response: GetPollResponse = { type: poll.type };
    if (poll.type == "string") {
      response.opinion = poll.opinions[user];
      if (opinionCountAboveThreshold) {
        const opinions = Object.values(poll.opinions);
        response.statistics = {
          counts: _.countBy(opinions),
        };
      }
    } else if (poll.type == "number") {
      response.opinion = poll.opinions[user];
      if (opinionCountAboveThreshold) {
        const opinions = Object.values(poll.opinions);
        response.statistics = {
          mean: math.mean(opinions),
          std: math.std(opinions),
        };
      }
    } else {
      throw new Error("BUG: unknown poll type");
    }
    return response;
  }
}
