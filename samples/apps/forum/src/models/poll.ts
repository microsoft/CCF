import * as ccf from "../types/ccf";

export namespace kv {
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

  export type PollMap = ccf.TypedKVMap<string, Poll>;

  export function getPollMap(): PollMap {
    return new ccf.TypedKVMap(ccf.kv.polls, ccf.string, ccf.json<kv.Poll>());
  }
}
