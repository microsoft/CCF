import * as _ from "lodash-es";
import * as math from "mathjs";

import { BadRequestError, ForbiddenError, NotFoundError } from "../error_handler.js";
import { getPollMap, MINIMUM_OPINION_THRESHOLD, Opinion, PollMap, PollSummary, PollType } from "../models/poll.js";

export class PollService {
  private kvPolls: PollMap;
  constructor() {
    this.kvPolls = getPollMap();
  }

  public getPollSummary(userId: string, topic: string) {
    if (!this.kvPolls.has(topic)) {
      throw new NotFoundError("Poll does not exist");
    }
    return this._getPollSummary(userId, topic);
  }

  public getPollSummaries(userId: string) {
    const summaries = new Map<string, PollSummary>();
    for (const topic of this._getTopics()) {
      summaries.set(topic, this._getPollSummary(userId, topic));
    }
    return summaries;
  }

  public createPoll(userId: string, topic: string, type: PollType) {
    if (this.kvPolls.has(topic)) {
      throw new ForbiddenError("Poll with given topic exists already");
    }
    this.kvPolls.set(topic, {
      creator: userId,
      type: type,
      opinions: {},
    });
  }

  public createPolls(userId: string, polls: Map<string, PollType>) {
    for (let [topic, type] of polls.entries()) {
      if (this.kvPolls.has(topic)) {
        throw new ForbiddenError(`Poll with topic '${topic}' exists already`);
      }
      this.kvPolls.set(topic, {
        creator: userId,
        type: type,
        opinions: {},
      });
    }
  }

  public submitOpinion(userId: string, topic: string, opinion: Opinion) {
    const poll = this.kvPolls.get(topic);
    if (poll === undefined) {
      throw new NotFoundError("Poll does not exist");
    }
    if (typeof opinion !== poll.type) {
      throw new BadRequestError("Poll has a different opinion type");
    }
    poll.opinions[userId] = opinion;
    this.kvPolls.set(topic, poll);
  }

  public submitOpinions(userId: string, opinions: Map<string, Opinion>) {
    for (const [topic, opinion] of opinions.entries()) {
      const poll = this.kvPolls.get(topic);
      if (poll === undefined) {
        throw new BadRequestError(`Poll with topic '${topic}' does not exist`);
      }
      if (typeof opinion !== poll.type) {
        throw new BadRequestError(
          `Poll with topic '${topic}' has a different opinion type`
        );
      }
      poll.opinions[userId] = opinion;
      this.kvPolls.set(topic, poll);
    }
  }

  private _getPollSummary(userId: string, topic: string): PollSummary {
    const poll = this.kvPolls.get(topic);
    if (poll === undefined) {
      throw new Error(`BUG: poll with topic '${topic}' does not exist`);
    }

    const opinionCountAboveThreshold =
      Object.keys(poll.opinions).length >= MINIMUM_OPINION_THRESHOLD;

    const response: PollSummary = { type: poll.type };
    if (poll.type == "string") {
      response.opinion = poll.opinions[userId];
      if (opinionCountAboveThreshold) {
        const opinions = Object.values(poll.opinions);
        response.statistics = {
          counts: _.countBy(opinions),
        };
      }
    } else if (poll.type == "number") {
      response.opinion = poll.opinions[userId];
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

  private _getTopics(): string[] {
    const topics = [];
    this.kvPolls.forEach((val, key) => {
      topics.push(key);
    });
    return topics;
  }
}
