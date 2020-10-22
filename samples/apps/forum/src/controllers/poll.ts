// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import {
    Body,
    Path,
    Header,
    SuccessResponse,
    Response,
    Controller,
    Get,
    Post,
    Put,
    Route,
} from "@tsoa/runtime";

import * as _ from 'lodash-es'
import * as math from 'mathjs'

import { ValidateErrorResponse, ValidateErrorStatus } from "../error_handler"
import { parseAuthToken } from "../util"
import * as ccf from "../types/ccf"

export const MINIMUM_OPINION_THRESHOLD = 10

interface ErrorResponse {
    message: string
}

interface CreatePollRequest {
    type: "string" | "number"
}

interface CreatePollsRequest {
    polls: { [topic: string]: CreatePollRequest }
}

type Opinion = string | number

interface SubmitOpinionRequest {
    opinion: Opinion
}

interface SubmitOpinionsRequest {
    opinions: { [topic: string]: SubmitOpinionRequest }
}

interface StringPollResponse {
    type: "string"
    statistics?: {
        counts: { [ opinion: string]: number}
    }
    opinion?: string
}

interface NumericPollResponse {
    type: "number"
    statistics?: {
        mean: number
        std: number
    }
    opinion?: number
}

type GetPollResponse = StringPollResponse | NumericPollResponse

interface GetPollsResponse {
    polls: { [topic: string]: GetPollResponse }
}

// Export REST API request/response types for unit tests
export {
    CreatePollRequest, SubmitOpinionRequest,
    CreatePollsRequest, SubmitOpinionsRequest,
    GetPollResponse, StringPollResponse, NumericPollResponse 
}

namespace kv {
    type User = string

    interface PollBase<T> {
        creator: string
        type: string
        opinions: Record<User, T>
    }

    interface StringPoll extends PollBase<string> {
        type: "string"
    }

    interface NumericPoll extends PollBase<number> {
        type: "number"
    }

    export type Poll = StringPoll | NumericPoll
}

// GET  /polls/{topic} return poll
// POST /polls/{topic} create poll
// PUT  /polls/{topic} submit opinion
// GET  /polls return all polls
// POST /polls create multiple polls
// PUT  /polls submit opinions for multiple polls


@Route("polls")
export class PollController extends Controller {

    private kvPolls = new ccf.TypedKVMap(ccf.kv.polls, ccf.string, ccf.json<kv.Poll>())
    private kvTopics = new ccf.TypedKVMap(ccf.kv.topics, ccf.string, ccf.json<string[]>())
    private kvTopicsKey = 'all'

    @SuccessResponse(201, "Poll has been successfully created")
    @Response<ErrorResponse>(403, "Poll has not been created because a poll with the same topic exists already")
    @Response<ValidateErrorResponse>(ValidateErrorStatus, "Schema validation error")
    @Post('{topic}')
    public createPoll(
        @Path() topic: string,
        @Body() body: CreatePollRequest,
        @Header() authorization: string,
    ): void {
        const user = parseAuthToken(authorization)

        if (this.kvPolls.has(topic)) {
            this.setStatus(403)
            return { message: "Poll with given topic exists already" } as any
        }
        this.kvPolls.set(topic, {
            creator: user,
            type: body.type,
            opinions: {}
        })
        const topics = this._getTopics()
        topics.push(topic)
        this.kvTopics.set(this.kvTopicsKey, topics)
        this.setStatus(201)
    }

    @SuccessResponse(201, "Polls have been successfully created")
    @Response<ErrorResponse>(403, "Polls were not created because a poll with the same topic exists already")
    @Response<ValidateErrorResponse>(ValidateErrorStatus, "Schema validation error")
    @Post()
    public createPolls(
        @Body() body: CreatePollsRequest,
        @Header() authorization: string,
    ): void {
        const user = parseAuthToken(authorization)

        for (let [topic, poll] of Object.entries(body.polls)) {
            if (this.kvPolls.has(topic)) {
                this.setStatus(403)
                return { message: `Poll with topic '${topic}' exists already` } as any
            }
            this.kvPolls.set(topic, {
                creator: user,
                type: poll.type,
                opinions: {}
            })
            const topics = this._getTopics()
            topics.push(topic)
            this.kvTopics.set(this.kvTopicsKey, topics)
        }
        this.setStatus(201)
    }

    @SuccessResponse(204, "Opinion has been successfully recorded")
    @Response<ErrorResponse>(400, "Opinion was not recorded because the opinion data type does not match the poll type")
    @Response<ErrorResponse>(404, "Opinion was not recorded because no poll with the given topic exists")
    @Response<ValidateErrorResponse>(ValidateErrorStatus, "Schema validation error")
    @Put('{topic}')
    public submitOpinion(
        @Path() topic: string,
        @Body() body: SubmitOpinionRequest,
        @Header() authorization: string,
    ): void {
        const user = parseAuthToken(authorization)

        const poll = this.kvPolls.get(topic)
        if (poll === undefined) {
            this.setStatus(404)
            return { message: "Poll does not exist" } as any
        }
        if (typeof body.opinion !== poll.type) {
            this.setStatus(400)
            return { message: "Poll has a different opinion type" } as any
        }      
        poll.opinions[user] = body.opinion
        this.kvPolls.set(topic, poll)
        this.setStatus(204)
    }

    @SuccessResponse(204, "Opinions have been successfully recorded")
    @Response<ErrorResponse>(400, "Opinions were not recorded because either an opinion data type did not match the poll type or a poll with the given topic was not found")
    @Response<ValidateErrorResponse>(ValidateErrorStatus, "Schema validation error")
    @Put()
    public submitOpinions(
        @Body() body: SubmitOpinionsRequest,
        @Header() authorization: string,
    ): void {
        const user = parseAuthToken(authorization)

        for (const [topic, opinion] of Object.entries(body.opinions)) {
            const poll = this.kvPolls.get(topic)
            if (poll === undefined) {
                this.setStatus(400)
                return { message: `Poll with topic '${topic}' does not exist` } as any
            }
            if (typeof opinion.opinion !== poll.type) {
                this.setStatus(400)
                return { message: `Poll with topic '${topic}' has a different opinion type` } as any
            }      
            poll.opinions[user] = opinion.opinion
            this.kvPolls.set(topic, poll)
        }

        this.setStatus(204)
    }

    @SuccessResponse(200, "Poll data")
    @Response<ErrorResponse>(404, "Poll data could not be returned because no poll with the given topic exists")
    @Response<ValidateErrorResponse>(ValidateErrorStatus, "Schema validation error")
    @Get('{topic}')
    public getPoll(
        @Path() topic: string,
        @Header() authorization: string,
    ): GetPollResponse {
        const user = parseAuthToken(authorization)

        if (!this.kvPolls.has(topic)){
            this.setStatus(404)
            return { message: "Poll does not exist" } as any
        }

        this.setStatus(200)
        return this._getPoll(user, topic)
    }
    
    @SuccessResponse(200, "Poll data")
    @Response<ValidateErrorResponse>(ValidateErrorStatus, "Schema validation error")
    @Get()
    public getPolls(
        @Header() authorization: string,
    ): GetPollsResponse {
        const user = parseAuthToken(authorization)

        let response: GetPollsResponse = { polls: {} }

        for (const topic of this._getTopics()) {
            response.polls[topic] = this._getPoll(user, topic)
        }

        this.setStatus(200)
        return response
    }

    _getTopics(): string[] {
        return this.kvTopics.get(this.kvTopicsKey) ?? []
    }

    _getPoll(user: string, topic: string): GetPollResponse {
        const poll = this.kvPolls.get(topic)
        if (poll === undefined) {
            throw new Error(`Poll with topic '${topic}' does not exist`)
        }

        const opinionCountAboveThreshold = Object.keys(poll.opinions).length >= MINIMUM_OPINION_THRESHOLD

        const response: GetPollResponse = { type: poll.type }
        // TODO can repetition be avoided while maintaining type checking?
        if (poll.type == "string") {
            response.opinion = poll.opinions[user]
            if (opinionCountAboveThreshold) {
                const opinions = Object.values(poll.opinions)
                response.statistics = {
                    counts: _.countBy(opinions)
                }
            }
        } else if (poll.type == "number") {
            response.opinion = poll.opinions[user]
            if (opinionCountAboveThreshold) {
                const opinions = Object.values(poll.opinions)
                response.statistics = {
                    mean: math.mean(opinions),
                    std: math.std(opinions)
                }
            }
        } else {
            throw new Error('unknown poll type')
        }
        return response
    }
}