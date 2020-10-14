
import {
    Body,
    Path,
    Controller,
    Get,
    Post,
    Put,
    Route,
} from "@tsoa/runtime";

import * as _ from 'lodash-es'
import * as math from 'mathjs'

import * as ccf from "../types/ccf"

const MINIMUM_OPINION_THRESHOLD = 3

interface CreatePollRequest {
    type: "string" | "number"
}

interface SubmitOpinionRequest {
    opinion: string | number
}

interface StringPollStatistics {
    counts: { [ opinion: string]: number}
}

interface NumericPollStatistics {
    // TODO should this be mean? otherwise we're leaking a concrete value
    median: number
    stddev: number
}

interface GetPollResponse {
    type: "string" | "number"
    statistics: StringPollStatistics | NumericPollStatistics
    opinion?: string | number
}

interface Poll {
    type: "string" | "number"
    opinions: { [user: string]: string | number }
}

const kvPolls = new ccf.TypedKVMap(ccf.kv.polls, ccf.string, ccf.json<Poll>())

@Route("polls")
export class PollController extends Controller {

    @Post('{topic}')
    public createPoll(
        @Path() topic: string,
        @Body() body: CreatePollRequest,
    ): void {
        // TODO .has() would be nice
        try {
            kvPolls.get(topic)
            // Poll exists.
            this.setStatus(403)
            return
        } catch (e) {
            // Poll does not exist, continue.
        }
        kvPolls.set(topic, {
            type: body.type,
            opinions: {}
        })
        this.setStatus(201)
    }

    @Put('{topic}')
    public submitOpinion(
        @Path() topic: string,
        @Body() body: SubmitOpinionRequest
    ): void {
        try {
            var poll = kvPolls.get(topic)
        } catch (e) {
            // Poll does not exist.
            this.setStatus(404)
            return
        }
        if (typeof body.opinion !== poll.type) {
            // Poll has a different opinion type.
            this.setStatus(400)
            return
        }
        // TODO
        const user = "foo"        
        poll.opinions[user] = body.opinion
        kvPolls.set(topic, poll)
        this.setStatus(200)
    }

    @Get('{topic}')
    public getPoll(
        @Path() topic: string
    ): GetPollResponse {
        try {
            var poll = kvPolls.get(topic)
        } catch (e) {
            // Poll does not exist.
            this.setStatus(404)
            return
        }

        const opinionCount = Object.keys(poll.opinions).length
        if (opinionCount < MINIMUM_OPINION_THRESHOLD) {
            this.setStatus(403)
            return
        }

        const opinions = Object.values(poll.opinions)

        let statistics: StringPollStatistics | NumericPollStatistics
        if (poll.type == "string") {
            statistics = {
                counts: _.countBy(opinions)
            }
        } else {
            statistics = {
                median: math.median(opinions as number[]),
                stddev: math.std(opinions as number[])
            }
        }

        // TODO
        const user = "foo"

        const response = {
            type: poll.type,
            opinion: poll.opinions[user],
            statistics: statistics
        }
        
        this.setStatus(200)
        return response
    }
}