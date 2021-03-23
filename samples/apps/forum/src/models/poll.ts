import * as ccfapp from "ccf-app";

type User = string;

interface PollBase<T> {
  creator: string;
  type: string;
  opinions: Record<User, T>;
}

interface StringPoll extends PollBase<string> {
  type: "string";
}

interface NumericPoll extends PollBase<number> {
  type: "number";
}

export type Poll = StringPoll | NumericPoll;

export type PollMap = ccfapp.TypedKvMap<string, Poll>;

export function getPollMap(): PollMap {
  return ccfapp.typedKv("polls", ccfapp.string, ccfapp.json<Poll>());
}
