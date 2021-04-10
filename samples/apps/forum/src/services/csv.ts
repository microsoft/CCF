import * as _ from "lodash-es";

// Need to use minified browser bundle to avoid pulling in Node.JS dependencies
import papa from "papaparse/papaparse.min.js";

import { BadRequestError } from "../error_handler.js";
import { getPollMap, PollMap } from "../models/poll.js";


export class CsvService {
  private kvPolls: PollMap;
  constructor() {
    this.kvPolls = getPollMap();
  }

  public getOpinions(userId: string): string {
    const rows = [];
    this.kvPolls.forEach((poll, topic) => {
      const opinion = poll.opinions[userId];
      if (opinion !== undefined) {
        rows.push({ Topic: topic, Opinion: opinion });
      }
    });

    const csv = papa.unparse(rows);
    return csv;
  }

  public submitOpinions(userId: string, csv: string) {
    const rows = papa.parse<any>(csv, { header: true }).data;

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
        poll.opinions[userId] = val;
      } else {
        poll.opinions[userId] = opinion;
      }
      this.kvPolls.set(topic, poll);
    }
  }
}
