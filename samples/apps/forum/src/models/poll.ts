import * as ccfapp from "@microsoft/ccf-app";

type User = string;

interface PollBase<T extends Opinion> {
  creator: string;
  type: PollType;
  opinions: Record<User, T>;
}

interface StringPoll extends PollBase<string> {
  type: "string";
}

interface NumericPoll extends PollBase<number> {
  type: "number";
}

export type PollType = "string" | "number";

export type Opinion = string | number;

export type Poll = StringPoll | NumericPoll;

export type PollMap = ccfapp.TypedKvMap<string, Poll>;

export interface StringPollSummary {
  type: "string";
  statistics?: {
    counts: { [opinion: string]: number };
  };
  opinion?: string;
}

export interface NumericPollSummary {
  type: "number";
  statistics?: {
    mean: number;
    std: number;
  };
  opinion?: number;
}

export type PollSummary = StringPollSummary | NumericPollSummary;

export function getPollMap(): PollMap {
  return ccfapp.typedKv("polls", ccfapp.string, ccfapp.json<Poll>());
}
