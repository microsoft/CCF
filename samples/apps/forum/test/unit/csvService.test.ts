import '@microsoft/ccf-app/polyfill';
import * as kv from '@microsoft/ccf-app/kv';
import { parse, unparse } from "papaparse";
import { assert } from "chai";

import { CsvService } from "../../src/services/csv";
import { PollService } from '../../src/services/poll';
import { getPollMap } from '../../src/models/poll';

beforeEach(function () {
  // clear KV before each test
  for (const prop of Object.getOwnPropertyNames(kv.rawKv)) {
    delete kv.rawKv[prop];
  }
});

describe("CsvService", function () {
  const pollService = new PollService();
  const csvService = new CsvService();

  describe("submitOpinions", function () {
    it("stores opinions from CSV", function () {
      const user = "user";
      const topicA = "a";
      const topicB = "b";
      const typeA = "number";
      const typeB = "string";
      const rows = [
        { Topic: topicA, Opinion: 1.4 },
        { Topic: topicB, Opinion: "foo" },
      ];
      const csv = unparse(rows);
      pollService.createPoll(user, topicA, typeA);
      pollService.createPoll(user, topicB, typeB);
      csvService.submitOpinions(user, csv);

      const pollMap = getPollMap();
      const actualA = pollMap.get(topicA);
      assert.equal(actualA.opinions[user], rows[0].Opinion);
      const actualB = pollMap.get(topicB);
      assert.equal(actualB.opinions[user], rows[1].Opinion);
    });
    it("returns opinions as CSV", function () {
      const user = "user";
      const topicA = "a";
      const topicB = "b";
      const typeA = "number";
      const typeB = "string";
      const opinionA = 1.2;
      const opinionB = "foo";
      pollService.createPoll(user, topicA, typeA);
      pollService.createPoll(user, topicB, typeB);
      pollService.submitOpinion(user, topicA, opinionA);
      pollService.submitOpinion(user, topicB, opinionB);

      const csvOut = csvService.getOpinions(user);
      const rowsOut = parse(csvOut, { header: true, dynamicTyping: true })
          .data;
      assert.deepEqual(rowsOut, [
        { Topic: topicA, Opinion: opinionA },
        { Topic: topicB, Opinion: opinionB },
      ]);
    })
  })
  
})