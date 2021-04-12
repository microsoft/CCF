import "@microsoft/ccf-app/polyfill";
import { assert } from "chai";

import {
  getPollMap,
  PollType,
  Opinion,
  NumericPollSummary,
  StringPollSummary,
} from "../../src/models/poll";
import { PollService } from "../../src/services/poll";
import { MINIMUM_OPINION_THRESHOLD } from "../../src/constants";

describe("PollService", function () {
  const pollService = new PollService();

  describe("createPoll", function () {
    const topic = "topic";
    const user = "user";
    it("creates numeric polls", function () {
      const type = "number";
      pollService.createPoll(user, topic, type);

      const pollMap = getPollMap();
      const actual = pollMap.get(topic);
      assert.equal(actual.creator, user);
      assert.equal(actual.type, type);
    });
    it("creates string polls", function () {
      const type = "string";
      pollService.createPoll(user, topic, type);

      const pollMap = getPollMap();
      const actual = pollMap.get(topic);
      assert.equal(actual.creator, user);
      assert.equal(actual.type, type);
    });
    it("rejects creating polls with an existing topic", function () {
      const type = "number";
      pollService.createPoll(user, topic, type);
      assert.throws(() => pollService.createPoll(user, topic, type));
    });
  });
  describe("createPolls", function () {
    it("creates multiple polls", function () {
      const user = "user";
      const topicA = "a";
      const topicB = "b";
      const typeA = "number";
      const typeB = "string";
      const polls = new Map<string, PollType>();
      polls.set(topicA, typeA);
      polls.set(topicB, typeB);
      pollService.createPolls(user, polls);

      const pollMap = getPollMap();
      const actualA = pollMap.get(topicA);
      assert.equal(actualA.type, typeA);
      const actualB = pollMap.get(topicB);
      assert.equal(actualB.type, typeB);
    });
    it("rejects creating polls with an existing topic", function () {
      const user = "user";
      const topic = "a";
      const type = "number";
      const polls = new Map<string, PollType>();
      polls.set(topic, type);
      pollService.createPolls(user, polls);
      assert.throws(() => pollService.createPolls(user, polls));
    });
  });
  describe("submitOpinion", function () {
    it("stores an opinion to a topic", function () {
      const user = "user";
      const topic = "a";
      const type = "number";
      const opinion = 1.2;
      pollService.createPoll(user, topic, type);
      pollService.submitOpinion(user, topic, opinion);

      const pollMap = getPollMap();
      const actual = pollMap.get(topic);
      assert.equal(actual.opinions[user], opinion);
    });
    it("rejects opinions with mismatching data type", function () {
      const user = "user";
      const topic = "a";
      const type = "number";
      pollService.createPoll(user, topic, type);
      assert.throws(() => pollService.submitOpinion(user, topic, "foo"));
    });
    it("rejects opinions for unknown topics", function () {
      const user = "user";
      const topic = "a";
      assert.throws(() => pollService.submitOpinion(user, topic, "foo"));
    });
  });
  describe("submitOpinions", function () {
    it("stores opinions to multiple topics", function () {
      const user = "user";
      const topicA = "a";
      const topicB = "b";
      const typeA = "number";
      const typeB = "string";
      const opinionA = 1.2;
      const opinionB = "foo";
      const opinions = new Map<string, Opinion>();
      opinions.set(topicA, opinionA);
      opinions.set(topicB, opinionB);
      pollService.createPoll(user, topicA, typeA);
      pollService.createPoll(user, topicB, typeB);
      pollService.submitOpinions(user, opinions);

      const pollMap = getPollMap();
      const actualA = pollMap.get(topicA);
      assert.equal(actualA.opinions[user], opinionA);
      const actualB = pollMap.get(topicB);
      assert.equal(actualB.opinions[user], opinionB);
    });
    it("rejects opinions with mismatching data type", function () {
      const user = "user";
      const topic = "a";
      const type = "number";
      const opinion = "foo";
      const opinions = new Map<string, Opinion>();
      opinions.set(topic, opinion);
      pollService.createPoll(user, topic, type);
      assert.throws(() => pollService.submitOpinions(user, opinions));
    });
    it("rejects opinions for unknown topics", function () {
      const user = "user";
      const topic = "a";
      const opinion = "foo";
      const opinions = new Map<string, Opinion>();
      opinions.set(topic, opinion);
      assert.throws(() => pollService.submitOpinions(user, opinions));
    });
  });
  describe("getPollSummary", function () {
    it("returns aggregated numeric poll opinions", function () {
      const user = "creator";
      const topic = "a";
      const type = "number";
      const opinions = [1.5, 0.9, 1.2, 1.5, 0.9, 1.2, 1.5, 0.9, 1.2, 1.5];
      pollService.createPoll(user, topic, type);
      for (const [i, opinion] of opinions.entries()) {
        pollService.submitOpinion(`user${i}`, topic, opinion);
      }

      const actual = pollService.getPollSummary(
        user,
        topic
      ) as NumericPollSummary;
      assert.equal(
        actual.statistics.mean,
        opinions.reduce((a, b) => a + b, 0) / opinions.length
      );
    });
    it("returns aggregated string poll opinions", function () {
      const user = "creator";
      const topic = "a";
      const type = "string";
      const opinions = [
        "foo",
        "foo",
        "bar",
        "foo",
        "foo",
        "bar",
        "foo",
        "foo",
        "bar",
        "foo",
      ];
      pollService.createPoll(user, topic, type);
      for (const [i, opinion] of opinions.entries()) {
        pollService.submitOpinion(`user${i}`, topic, opinion);
      }

      const actual = pollService.getPollSummary(
        user,
        topic
      ) as StringPollSummary;
      assert.equal(actual.statistics.counts["foo"], 7);
      assert.equal(actual.statistics.counts["bar"], 3);
    });
    it("rejects returning aggregated opinions below the required opinion count threshold", function () {
      const user = "creator";
      const topic = "a";
      const type = "string";
      pollService.createPoll(user, topic, type);
      for (let i = 0; i < MINIMUM_OPINION_THRESHOLD - 1; i++) {
        pollService.submitOpinion(`user${i}`, topic, "foo");
      }

      const actual = pollService.getPollSummary(user, topic);
      assert.notExists(actual.statistics);
    });
    it("rejects returning aggregated opinions for unknown topics", function () {
      const user = "creator";
      assert.throws(() => pollService.getPollSummary(user, "foo"));
    });
  });
});
